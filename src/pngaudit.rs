//! PNG 结构完整性审计（对标 pngcheck 类容器结构检查）。
//!
//! 与 [`crate::pngcrack`]（只爆破 IHDR 宽高）、[`crate::carve`]（magic 雕刻）不同，
//! 本模块从原始字节逐块重解析 PNG，按 RFC 2083 / ISO 15948 的核心规则检查：
//! 签名、每块 CRC32、IHDR 首位/唯一与字段合法性、IEND 末位/唯一与 IEND 后追加
//! 数据、IDAT 连续性、未知关键块（critical chunk）以及截断/越界。
//!
//! 能力红线：只校验 **PNG 容器结构**，回答"文件是否被手工篡改/拼接"，不检测像素
//! 域 LSB 隐写（卡方/位平面的职责），也不做 PLTE/tRNS/APNG 等深度语义校验与 zlib
//! 流内部完整性检查。核心为零 IO 纯函数，截断/越界一律降级为 issue 而非 panic。

use crate::pngcrack::crc32_table;

/// PNG 8 字节签名。
const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const IHDR: [u8; 4] = *b"IHDR";
const PLTE: [u8; 4] = *b"PLTE";
const IDAT: [u8; 4] = *b"IDAT";
const IEND: [u8; 4] = *b"IEND";

/// 标准关键块（critical）白名单，首字母大写的其余块均为非标准关键块。
const CRITICAL_WHITELIST: [[u8; 4]; 4] = [IHDR, PLTE, IDAT, IEND];

/// 问题严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 结构违规、CRC 失配、截断等明确错误
    Error,
    /// 可疑但不一定非法，如 IEND 后追加数据、IDAT 被夹断
    Warn,
    /// 信息性提示
    Info,
}

impl Severity {
    /// 中文标签。
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "错误",
            Severity::Warn => "警告",
            Severity::Info => "信息",
        }
    }
}

/// 单条审计发现。
#[derive(Debug, Clone)]
pub struct AuditIssue {
    /// 严重级别
    pub severity: Severity,
    /// 关联块类型；文件级问题为 None
    pub chunk: Option<[u8; 4]>,
    /// 问题字节偏移（块长度字段起点；文件级问题为 0）
    pub offset: usize,
    /// 中文描述（技术标识保留英文）
    pub message: String,
}

/// 整张 PNG 的审计报告。
#[derive(Debug, Clone)]
pub struct PngAuditReport {
    /// 成功解析出的块数量
    pub chunk_count: usize,
    /// 按发现顺序排列的问题列表
    pub issues: Vec<AuditIssue>,
}

impl PngAuditReport {
    /// 指定严重级别的问题计数。
    pub fn count(&self, sev: Severity) -> usize {
        self.issues.iter().filter(|i| i.severity == sev).count()
    }
}

/// 解析出的原始块（保留偏移，供审计）。
struct RawChunk {
    ty: [u8; 4],
    data: Vec<u8>,
    /// 块长度字段的绝对偏移
    offset: usize,
}

/// 对"类型(4)+数据"增量计算 CRC32，零拷贝复用 pngcrack 的查表实现。
fn crc32_chunk(ty: &[u8; 4], data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in ty.iter().chain(data) {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// 判断位深×颜色类型组合是否合法（RFC 2083 表）。
fn valid_ihdr_format(color_type: u8, bit_depth: u8) -> bool {
    matches!(
        (color_type, bit_depth),
        (0, 1 | 2 | 4 | 8 | 16) | (2, 8 | 16) | (3, 1 | 2 | 4 | 8) | (4, 8 | 16) | (6, 8 | 16)
    )
}

/// PNG 结构审计入口：输入完整文件字节，输出报告（零 IO、零 panic）。
pub fn audit(raw: &[u8]) -> PngAuditReport {
    let mut issues: Vec<AuditIssue> = Vec::new();
    let mut push = |severity: Severity, chunk: Option<[u8; 4]>, offset: usize, message: String| {
        issues.push(AuditIssue {
            severity,
            chunk,
            offset,
            message,
        });
    };

    // 1. 签名校验
    if raw.len() < 8 || raw[0..8] != SIG {
        push(
            Severity::Error,
            None,
            0,
            "无效 PNG 签名（缺少 89 50 4E 47 0D 0A 1A 0A）".to_string(),
        );
        return PngAuditReport {
            chunk_count: 0,
            issues,
        };
    }

    // 2. 逐块解析（带越界防护）
    let mut chunks: Vec<RawChunk> = Vec::new();
    let mut pos = 8usize;
    let mut truncated = false;
    while pos < raw.len() {
        if pos + 8 > raw.len() {
            push(
                Severity::Error,
                None,
                pos,
                "块头部被截断（不足 length+type 共 8 字节）".to_string(),
            );
            truncated = true;
            break;
        }
        let length = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        let ty: [u8; 4] = raw[pos + 4..pos + 8].try_into().unwrap();
        let data_start = pos + 8;
        let data_end = data_start + length;
        let crc_end = data_end + 4;
        if crc_end > raw.len() {
            push(
                Severity::Error,
                Some(ty),
                pos,
                format!("块长度 {length} 越界，数据或 CRC 被截断"),
            );
            truncated = true;
            break;
        }

        // 块类型必须是 4 个 ASCII 字母
        if !ty.iter().all(u8::is_ascii_alphabetic) {
            push(
                Severity::Warn,
                Some(ty),
                pos,
                "块类型含非 ASCII 字母字节，不符合 PNG 命名约定".to_string(),
            );
        }

        let data = raw[data_start..data_end].to_vec();
        let stored_crc = u32::from_be_bytes(raw[data_end..crc_end].try_into().unwrap());

        // 3. 每块 CRC32 校验（范围 = 类型 + 数据）
        let calc_crc = crc32_chunk(&ty, &data);
        if calc_crc != stored_crc {
            push(
                Severity::Error,
                Some(ty),
                pos,
                format!(
                    "{} CRC32 失配：文件={:08X} 计算={:08X}",
                    String::from_utf8_lossy(&ty),
                    stored_crc,
                    calc_crc
                ),
            );
        }

        chunks.push(RawChunk {
            ty,
            data,
            offset: pos,
        });
        pos = crc_end;
        if ty == IEND {
            break;
        }
    }

    if chunks.is_empty() {
        push(
            Severity::Error,
            None,
            pos,
            "未解析到任何 PNG 块".to_string(),
        );
        return PngAuditReport {
            chunk_count: 0,
            issues,
        };
    }

    // 4. IHDR 必须为首块且唯一
    let ihdr_count = chunks.iter().filter(|c| c.ty == IHDR).count();
    if chunks[0].ty != IHDR {
        push(
            Severity::Error,
            Some(chunks[0].ty),
            chunks[0].offset,
            format!(
                "首块应为 IHDR，实际为 {}",
                String::from_utf8_lossy(&chunks[0].ty)
            ),
        );
    }
    if ihdr_count == 0 {
        push(Severity::Error, None, 0, "缺少 IHDR 块".to_string());
    } else if ihdr_count > 1 {
        push(
            Severity::Error,
            Some(IHDR),
            0,
            format!("IHDR 块不唯一，出现 {ihdr_count} 次"),
        );
    } else if let Some(ihdr) = chunks.iter().find(|c| c.ty == IHDR) {
        // 5. IHDR 13 字节字段合法性
        if ihdr.data.len() != 13 {
            push(
                Severity::Error,
                Some(IHDR),
                ihdr.offset,
                format!("IHDR 数据长度应为 13，实际为 {}", ihdr.data.len()),
            );
        } else {
            let d = &ihdr.data;
            let width = u32::from_be_bytes(d[0..4].try_into().unwrap());
            let height = u32::from_be_bytes(d[4..8].try_into().unwrap());
            let bit_depth = d[8];
            let color_type = d[9];
            let compression = d[10];
            let filter = d[11];
            let interlace = d[12];
            if width == 0 || height == 0 || width > 0x7FFF_FFFF || height > 0x7FFF_FFFF {
                push(
                    Severity::Error,
                    Some(IHDR),
                    ihdr.offset,
                    format!("IHDR 宽高非法：width={width} height={height}"),
                );
            }
            if !valid_ihdr_format(color_type, bit_depth) {
                push(
                    Severity::Error,
                    Some(IHDR),
                    ihdr.offset,
                    format!(
                        "IHDR 位深×颜色类型非法组合：color_type={color_type} bit_depth={bit_depth}"
                    ),
                );
            }
            if compression != 0 {
                push(
                    Severity::Error,
                    Some(IHDR),
                    ihdr.offset,
                    format!("IHDR 压缩方法仅允许 0，实际为 {compression}"),
                );
            }
            if filter != 0 {
                push(
                    Severity::Error,
                    Some(IHDR),
                    ihdr.offset,
                    format!("IHDR 过滤方法仅允许 0，实际为 {filter}"),
                );
            }
            if interlace > 1 {
                push(
                    Severity::Error,
                    Some(IHDR),
                    ihdr.offset,
                    format!("IHDR 隔行方式仅允许 0/1，实际为 {interlace}"),
                );
            }
        }
    }

    // 6. IEND 唯一性与末位
    let iend_count = chunks.iter().filter(|c| c.ty == IEND).count();
    if iend_count == 0 {
        push(Severity::Error, Some(IEND), 0, "缺少 IEND 块".to_string());
    } else {
        if iend_count > 1 {
            push(
                Severity::Error,
                Some(IEND),
                0,
                format!("IEND 块不唯一，出现 {iend_count} 次"),
            );
        }
        if chunks.last().map(|c| c.ty) != Some(IEND) {
            push(
                Severity::Error,
                Some(IEND),
                0,
                "IEND 不是最后一个块".to_string(),
            );
        }
        // IEND 之后的追加数据（仅在未截断时才有意义）
        if !truncated && pos < raw.len() {
            let trailing = raw.len() - pos;
            push(
                Severity::Warn,
                Some(IEND),
                pos,
                format!("IEND 之后存在 {trailing} 字节追加数据（常见于文件拼接/隐藏容器）"),
            );
        }
    }

    // 7. 多个 IDAT 必须连续（中间不得夹其他块）
    let idat_indexes: Vec<usize> = chunks
        .iter()
        .enumerate()
        .filter(|(_, c)| c.ty == IDAT)
        .map(|(i, _)| i)
        .collect();
    if idat_indexes.len() > 1 {
        let contiguous = idat_indexes.windows(2).all(|w| w[1] == w[0] + 1);
        if !contiguous
            && let Some(first) = idat_indexes.first()
            && let Some(c) = chunks.get(*first)
        {
            push(
                Severity::Warn,
                Some(IDAT),
                c.offset,
                "多个 IDAT 块不连续，中间夹有其他块".to_string(),
            );
        }
    }

    // 8. 未知关键块（首字母大写且不在标准白名单）
    for c in &chunks {
        let is_critical = c.ty[0].is_ascii_uppercase();
        if is_critical && !CRITICAL_WHITELIST.contains(&c.ty) {
            push(
                Severity::Warn,
                Some(c.ty),
                c.offset,
                format!(
                    "非标准关键块 {}（标准解码器可能拒绝）",
                    String::from_utf8_lossy(&c.ty)
                ),
            );
        }
    }

    PngAuditReport {
        chunk_count: chunks.len(),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 CRC 正确的块字节（length+type+data+crc）。
    fn make_chunk(ty: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ty);
        out.extend_from_slice(data);
        let crc = crc32_chunk(ty, data);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    /// 合法 IHDR 数据（1×1 RGBA 8bit）。
    fn ihdr_data() -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&1u32.to_be_bytes()); // width
        d.extend_from_slice(&1u32.to_be_bytes()); // height
        d.extend_from_slice(&[8u8, 6, 0, 0, 0]); // bit8, color6, comp/filter/interlace=0
        d
    }

    /// 用给定块拼出最小合法 PNG。
    fn make_png(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut raw = SIG.to_vec();
        raw.extend(make_chunk(&IHDR, &ihdr_data()));
        for c in extra {
            raw.extend_from_slice(c);
        }
        raw.extend(make_chunk(&IDAT, b"fake-idat"));
        raw.extend(make_chunk(&IEND, &[]));
        raw
    }

    #[test]
    fn valid_minimal_png_has_no_issues() {
        let raw = make_png(&[]);
        let report = audit(&raw);
        assert!(
            report.issues.is_empty(),
            "合法 PNG 不应有问题: {:?}",
            report.issues
        );
        assert_eq!(report.chunk_count, 3);
    }

    #[test]
    fn bad_signature_is_error() {
        let mut raw = make_png(&[]);
        raw[0] = 0;
        let report = audit(&raw);
        assert!(report.count(Severity::Error) > 0);
    }

    #[test]
    fn tampered_iend_crc_is_error() {
        let mut raw = make_png(&[]);
        // 翻转 IEND 的 CRC 首字节（IEND 是最后一块，CRC 在文件末尾 4 字节）
        let n = raw.len();
        raw[n - 4] ^= 0xFF;
        let report = audit(&raw);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.chunk == Some(IEND))
        );
    }

    #[test]
    fn trailing_bytes_after_iend_is_warn() {
        let mut raw = make_png(&[]);
        raw.extend_from_slice(b"hidden-after-iend");
        let report = audit(&raw);
        let warn = report
            .issues
            .iter()
            .find(|i| i.severity == Severity::Warn && i.message.contains("IEND 之后"))
            .expect("应报 IEND 后追加数据");
        assert!(warn.message.contains("17"));
    }

    #[test]
    fn ihdr_not_first_is_error() {
        let text = make_chunk(b"tEXt", b"key\x00val");
        let mut raw = SIG.to_vec();
        raw.extend(text);
        raw.extend(make_chunk(&IHDR, &ihdr_data()));
        raw.extend(make_chunk(&IDAT, b"x"));
        raw.extend(make_chunk(&IEND, &[]));
        let report = audit(&raw);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("首块应为 IHDR"))
        );
    }

    #[test]
    fn duplicate_ihdr_is_error() {
        let mut raw = make_png(&[]);
        // 在 IDAT 前再插一个 IHDR
        let second = make_chunk(&IHDR, &ihdr_data());
        let idat_pos = raw.windows(4).position(|w| w == IDAT).unwrap() - 4;
        raw.splice(idat_pos..idat_pos, second);
        let report = audit(&raw);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.message.contains("IHDR 块不唯一"))
        );
    }

    #[test]
    fn invalid_ihdr_format_and_zero_dimension() {
        // 非法组合：color_type=2(RGB) 不允许 bit_depth=4
        let mut d = Vec::new();
        d.extend_from_slice(&1u32.to_be_bytes());
        d.extend_from_slice(&1u32.to_be_bytes());
        d.extend_from_slice(&[4u8, 2, 0, 0, 0]);
        let mut raw = SIG.to_vec();
        raw.extend(make_chunk(&IHDR, &d));
        raw.extend(make_chunk(&IDAT, b"x"));
        raw.extend(make_chunk(&IEND, &[]));
        assert!(
            audit(&raw)
                .issues
                .iter()
                .any(|i| i.message.contains("位深×颜色类型非法"))
        );

        // 宽为 0
        let mut d0 = Vec::new();
        d0.extend_from_slice(&0u32.to_be_bytes());
        d0.extend_from_slice(&1u32.to_be_bytes());
        d0.extend_from_slice(&[8u8, 6, 0, 0, 0]);
        let mut raw0 = SIG.to_vec();
        raw0.extend(make_chunk(&IHDR, &d0));
        raw0.extend(make_chunk(&IDAT, b"x"));
        raw0.extend(make_chunk(&IEND, &[]));
        assert!(
            audit(&raw0)
                .issues
                .iter()
                .any(|i| i.message.contains("宽高非法"))
        );
    }

    #[test]
    fn non_contiguous_idat_is_warn_but_contiguous_ok() {
        let idat1 = make_chunk(&IDAT, b"aaaa");
        let idat2 = make_chunk(&IDAT, b"bbbb");
        let text = make_chunk(b"tEXt", b"k\x00v");

        // 连续两个 IDAT：不报警
        let mut ok = SIG.to_vec();
        ok.extend(make_chunk(&IHDR, &ihdr_data()));
        ok.extend(idat1.clone());
        ok.extend(idat2.clone());
        ok.extend(make_chunk(&IEND, &[]));
        assert!(
            !audit(&ok)
                .issues
                .iter()
                .any(|i| i.message.contains("IDAT 块不连续"))
        );

        // IDAT 中间夹 tEXt：报警
        let mut bad = SIG.to_vec();
        bad.extend(make_chunk(&IHDR, &ihdr_data()));
        bad.extend(idat1);
        bad.extend(text);
        bad.extend(idat2);
        bad.extend(make_chunk(&IEND, &[]));
        assert!(
            audit(&bad)
                .issues
                .iter()
                .any(|i| i.severity == Severity::Warn && i.message.contains("IDAT 块不连续"))
        );
    }

    #[test]
    fn unknown_critical_warns_but_ancillary_silent() {
        // 首字母大写 = 非标准关键块 → Warn
        let crit = make_chunk(b"XYZa", b"x");
        let raw_crit = make_png(&[crit]);
        assert!(
            audit(&raw_crit)
                .issues
                .iter()
                .any(|i| i.severity == Severity::Warn && i.message.contains("非标准关键块"))
        );

        // 首字母小写 = ancillary，即使非标准也不报警
        let anc = make_chunk(b"xYZa", b"x");
        let raw_anc = make_png(&[anc]);
        assert!(
            !audit(&raw_anc)
                .issues
                .iter()
                .any(|i| i.message.contains("非标准关键块"))
        );
    }

    #[test]
    fn truncated_chunk_does_not_panic() {
        let raw = make_png(&[]);
        // 砍掉末尾 10 字节，使最后一块不完整
        let cut = &raw[..raw.len() - 10];
        let report = audit(cut);
        assert!(report.count(Severity::Error) > 0);
    }
}
