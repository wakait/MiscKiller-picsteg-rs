//! 内置文件类型识别（替代外部 `file` 命令，跨平台零依赖）。
//!
//! 旧实现通过 `Command::new("file")` 调用系统命令，在原生 Windows 上因缺少
//! 该命令而静默失效。本模块用纯 Rust 的魔数匹配 + 文本特征判定给出 GNU file
//! 风格的英文描述，三平台行为一致且可单元测试。识别不了的数据返回 `None`，
//! 等价于旧实现 `IGNORES` 列表（data/empty 等不报告）的过滤效果。
//!
//! 注意：描述字符串中的英文关键词（bitmap/jpeg/pdf/zip/rar/7z 等）需与
//! [`crate::result::DetectResult::FileType`] 的高亮逻辑保持一致，不可随意翻译。

/// 一条二进制魔数规则：在固定偏移处匹配前缀，命中则输出对应英文描述。
struct Magic {
    /// 魔数出现的起始偏移
    offset: usize,
    /// 前缀字节
    magic: &'static [u8],
    /// GNU file 风格英文描述（含 result.rs 高亮所需关键词）
    desc: &'static str,
}

/// 内置魔数表。顺序即匹配优先级：更具体、更长的规则靠前，避免被短前缀抢占。
fn magics() -> [Magic; 31] {
    [
        // ---- 图像 ----
        Magic {
            offset: 0,
            magic: b"\x89PNG\r\n\x1a\n",
            desc: "png image data",
        },
        Magic {
            offset: 0,
            magic: b"\xFF\xD8\xFF",
            desc: "jpeg image data",
        },
        Magic {
            offset: 0,
            magic: b"GIF87a",
            desc: "GIF image data",
        },
        Magic {
            offset: 0,
            magic: b"GIF89a",
            desc: "GIF image data",
        },
        Magic {
            offset: 0,
            magic: b"BM",
            desc: "pc bitmap, Windows BMP format",
        },
        Magic {
            offset: 0,
            magic: b"\x00\x00\x01\x00",
            desc: "MS Windows icon resource",
        },
        // RIFF 容器需按偏移 8 的 FourCC 进一步区分 WebP/WAV/AVI
        Magic {
            offset: 0,
            magic: b"RIFF",
            desc: "RIFF (little-endian) data",
        },
        Magic {
            offset: 0,
            magic: b"OggS",
            desc: "Ogg data",
        },
        // ---- 文档 ----
        Magic {
            offset: 0,
            magic: b"%PDF-",
            desc: "pdf document",
        },
        Magic {
            offset: 0,
            magic: b"{\\rtf",
            desc: "Rich Text Format data",
        },
        // ---- 压缩包 / 归档 ----
        Magic {
            offset: 0,
            magic: b"PK\x03\x04",
            desc: "zip archive data",
        },
        Magic {
            offset: 0,
            magic: b"PK\x05\x06",
            desc: "zip archive data (empty)",
        },
        Magic {
            offset: 0,
            magic: b"Rar!\x1A\x07\x00",
            desc: "rar archive data",
        },
        Magic {
            offset: 0,
            magic: b"Rar!\x1A\x07\x01\x00",
            desc: "rar archive data, v5",
        },
        Magic {
            offset: 0,
            magic: b"7z\xBC\xAF\x27\x1C",
            desc: "7-zip archive data",
        },
        Magic {
            offset: 0,
            magic: b"\x1F\x8B\x08",
            desc: "gzip compressed data",
        },
        Magic {
            offset: 0,
            magic: b"BZh",
            desc: "bzip2 compressed data",
        },
        Magic {
            offset: 0,
            magic: b"\xFD7zXZ\x00",
            desc: "XZ compressed data",
        },
        Magic {
            offset: 0,
            magic: b"MSCF",
            desc: "Microsoft Cabinet archive data",
        },
        // tar 的魔数 ustar 位于偏移 257
        Magic {
            offset: 257,
            magic: b"ustar",
            desc: "POSIX tar archive",
        },
        // ---- 可执行 / 字节码 ----
        Magic {
            offset: 0,
            magic: b"MZ",
            desc: "PE32+ executable (console) x86-64, for MS Windows",
        },
        Magic {
            offset: 0,
            magic: b"\x7FELF",
            desc: "ELF executable",
        },
        Magic {
            offset: 0,
            magic: b"\xCA\xFE\xBA\xBE",
            desc: "Java class data",
        },
        // Mach-O 胖二进制（魔数后为大端架构数量）
        Magic {
            offset: 0,
            magic: b"\xCA\xFE\xBA\xBF",
            desc: "Mach-O universal binary",
        },
        Magic {
            offset: 0,
            magic: b"\xCF\xFA\xED\xFE",
            desc: "Mach-O 64-bit executable",
        },
        Magic {
            offset: 0,
            magic: b"\xCE\xFA\xED\xFE",
            desc: "Mach-O executable",
        },
        Magic {
            offset: 0,
            magic: b"\xFE\xED\xFA\xCF",
            desc: "Mach-O 64-bit executable",
        },
        Magic {
            offset: 0,
            magic: b"\xFE\xED\xFA\xCE",
            desc: "Mach-O executable",
        },
        // ---- 数据库 / 其他 ----
        Magic {
            offset: 0,
            magic: b"SQLite format 3\x00",
            desc: "SQLite database",
        },
        Magic {
            offset: 0,
            magic: b"ID3",
            desc: "Audio file with ID3 tag",
        },
        Magic {
            offset: 0,
            magic: b"fLaC",
            desc: "FLAC audio bitstream data",
        },
    ]
}

/// 判定字节是否为可打印 ASCII 或常见文本空白（与 strings.rs 口径一致）。
fn is_text_byte(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\r' | b'\n')
}

/// RIFF 容器按偏移 8 的 FourCC 区分为 WebP/WAV/AVI，无法区分时回退通用描述。
fn describe_riff(data: &[u8]) -> String {
    if data.len() >= 12 {
        match &data[8..12] {
            b"WEBP" => return "RIFF (little-endian) WebP image data".to_string(),
            b"WAVE" => return "RIFF (little-endian) WAVE audio data".to_string(),
            b"AVI " => return "RIFF (little-endian) AVI video data".to_string(),
            _ => {}
        }
    }
    "RIFF (little-endian) data".to_string()
}

/// 检测 UTF-16 文本：`可打印字节, 0x00`（LE）或 `0x00, 可打印字节`（BE）交替占比高。
fn detect_utf16(data: &[u8]) -> Option<String> {
    if data.len() < 8 || !data.len().is_multiple_of(2) {
        return None;
    }
    let mut le = 0usize;
    let mut be = 0usize;
    let pairs = data.len() / 2;
    for chunk in data.as_chunks::<2>().0 {
        if chunk[1] == 0 && is_text_byte(chunk[0]) {
            le += 1;
        }
        if chunk[0] == 0 && is_text_byte(chunk[1]) {
            be += 1;
        }
    }
    // 至少 2/3 的双字节单元符合某一端序，判定为 UTF-16 文本
    let threshold = pairs * 2 / 3;
    let bom_le = data.starts_with(b"\xFF\xFE");
    let bom_be = data.starts_with(b"\xFE\xFF");
    if le >= threshold && le >= be {
        let suffix = if bom_le {
            ", UTF-16 (with BOM)"
        } else {
            ", UTF-16 LE text"
        };
        Some(format!("Unicode text{}", suffix))
    } else if be >= threshold {
        let suffix = if bom_be {
            ", UTF-16 (with BOM)"
        } else {
            ", UTF-16 BE text"
        };
        Some(format!("Unicode text{}", suffix))
    } else {
        None
    }
}

/// 检测 ASCII / UTF-8 文本：可打印与常见空白占比足够高即认定为文本。
fn detect_text(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let printable = data.iter().filter(|b| is_text_byte(**b)).count();
    // 90% 阈值，兼顾少量控制字符的真实文本
    if printable * 10 < data.len() * 9 {
        return None;
    }

    // 跳过开头空白/BOM 后取首行判断特殊文本类型
    let mut start = data;
    if start.starts_with(b"\xEF\xBB\xBF") {
        start = &start[3..];
    }
    let trimmed = start
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| &start[i..]);

    if let Some(head) = trimmed {
        if head.starts_with(b"#!") {
            return Some("script text executable".to_string());
        }
        if head.starts_with(b"<?xml") {
            return Some("XML document text".to_string());
        }
    }

    // 含非 ASCII 的 UTF-8 多字节序列则标注 Unicode，否则为纯 ASCII
    if data.iter().any(|b| *b >= 0x80) {
        Some("UTF-8 Unicode text".to_string())
    } else {
        Some("ASCII text".to_string())
    }
}

/// 内置文件类型识别入口。数据过短或无法识别时返回 `None`。
pub fn detect(data: &[u8]) -> Option<String> {
    // 沿用旧实现的最小长度门槛
    const MIN_DATA_SIZE: usize = 5;
    if data.len() < MIN_DATA_SIZE {
        return None;
    }

    // 1. 二进制魔数匹配
    for rule in magics() {
        if let Some(slice) = data.get(rule.offset..rule.offset + rule.magic.len())
            && slice == rule.magic
        {
            // RIFF 需二次区分具体容器
            if rule.magic == b"RIFF" {
                return Some(describe_riff(data));
            }
            return Some(rule.desc.to_string());
        }
    }

    // 2. UTF-16 文本（先于单字节文本，避免被 ASCII 判定抢占）
    if let Some(desc) = detect_utf16(data) {
        return Some(desc);
    }

    // 3. ASCII / UTF-8 文本
    detect_text(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_png_and_keeps_highlight_keyword() {
        let data = b"\x89PNG\r\n\x1a\n rest of png";
        let desc = detect(data).expect("应识别 PNG");
        assert!(desc.contains("png"));
    }

    #[test]
    fn detects_zip_pdf_bmp_jpeg() {
        assert!(
            detect(b"PK\x03\x04 zip body padding")
                .unwrap()
                .contains("zip")
        );
        assert!(detect(b"%PDF-1.7 body padding").unwrap().contains("pdf"));
        assert!(
            detect(b"BM bitmap header padding")
                .unwrap()
                .contains("bitmap")
        );
        assert!(
            detect(b"\xFF\xD8\xFF\xE0 jpeg body")
                .unwrap()
                .contains("jpeg")
        );
    }

    #[test]
    fn detects_pe_elf_and_gzip() {
        assert!(
            detect(b"MZ pe header padding data")
                .unwrap()
                .contains("PE32")
        );
        assert!(detect(b"\x7FELF elf body padding").unwrap().contains("ELF"));
        assert!(
            detect(b"\x1F\x8B\x08 gzip stream")
                .unwrap()
                .contains("gzip")
        );
    }

    #[test]
    fn distinguishes_riff_containers() {
        let mut webp = vec![b'R', b'I', b'F', b'F'];
        webp.extend_from_slice(b"\x00\x00\x00\x00WEBPrest");
        assert!(detect(&webp).unwrap().contains("WebP"));
    }

    #[test]
    fn detects_ascii_and_shebang_script() {
        assert_eq!(detect(b"plain ascii text content").unwrap(), "ASCII text");
        let script = b"#!/bin/sh\necho hello\n";
        assert_eq!(detect(script).unwrap(), "script text executable");
    }

    #[test]
    fn detects_utf16le_with_bom() {
        // "Hi!" 的 UTF-16LE，前置 BOM FF FE，并补足长度
        let data = [0xFFu8, 0xFE, b'H', 0, b'i', 0, b'!', 0, b'!', 0];
        let desc = detect(&data).expect("应识别 UTF-16");
        assert!(desc.contains("UTF-16"));
    }

    #[test]
    fn rejects_random_and_short_bytes() {
        // 随机二进制无可识别特征
        let random = vec![0xABu8; 64];
        assert!(detect(&random).is_none());
        // 短于最小门槛
        assert!(detect(b"abc").is_none());
    }

    #[test]
    fn binary_magic_not_misclassified_as_text() {
        let data = b"%PDF-1.4 binary-ish content here";
        // 魔数优先级高于文本判定
        assert!(detect(data).unwrap().starts_with("pdf"));
    }
}
