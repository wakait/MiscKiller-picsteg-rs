//! PNG 宽高 CRC 爆破（对标 stegsolve/PNG 尺寸修复类 CTF 考点）。
//!
//! IHDR 结构：`length(4) | "IHDR"(4) | width(4) | height(4) | bitdepth(1)
//! | colortype(1) | compression(1) | filter(1) | interlace(1) | CRC32(4)`
//! CRC32 计算范围为类型字节 + 13 字节数据。攻击者常改小宽/高使图片只显示部分内容，
//! 但保留正确 CRC。本模块在 CRC 已知的前提下，遍历候选 width/height 重算 CRC，
//! 找到与文件内 CRC 一致的组合，即还原真实尺寸。

/// IHDR 爆破结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IhdrGuess {
    pub width: u32,
    pub height: u32,
}

// 标准 CRC32（IEEE 802.3，与 PNG/zlib 一致），查表实现避免额外依赖
fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// 定位 IHDR 块并返回 (数据起始绝对偏移, 块内 width/height 偏移信息)。
/// 数据起始 = IHDR 类型字段位置（CRC 从类型开始算）。
fn locate_ihdr(raw: &[u8]) -> Option<usize> {
    const SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if raw.len() < 8 || raw[0..8] != SIG {
        return None;
    }
    // 签名后第一个块即 IHDR
    if raw.len() < 12 || &raw[12..16] != b"IHDR" {
        return None;
    }
    Some(12) // 类型字段 "IHDR" 的绝对偏移
}

/// 计算指定 width/height 下 IHDR 的 CRC（仅替换宽高，其余字节不变）。
/// `type_off` 为 "IHDR" 类型字段偏移，CRC 输入 = 类型(4) + 数据(13)。
fn crc_for_dimensions(raw: &[u8], type_off: usize, width: u32, height: u32) -> u32 {
    let mut buf = [0u8; 17]; // 4 类型 + 13 数据
    buf[0..4].copy_from_slice(&raw[type_off..type_off + 4]);
    let data_off = type_off + 4;
    buf[4..17].copy_from_slice(&raw[data_off..data_off + 13]);
    buf[4..8].copy_from_slice(&width.to_be_bytes());
    buf[8..12].copy_from_slice(&height.to_be_bytes());
    crc32(&buf)
}

/// 爆破 IHDR 真实宽高。
/// - `max_dim`：候选宽高上限（基于文件体积给出合理上界，默认 65535）
/// - 优先在已知宽高附近搜索；返回所有使 CRC 匹配的组合（通常唯一）。
pub fn brute_force_dimensions(raw: &[u8], max_dim: u32) -> Vec<IhdrGuess> {
    let Some(type_off) = locate_ihdr(raw) else {
        return Vec::new();
    };
    let data_off = type_off + 4;
    let stored_crc = u32::from_be_bytes([
        raw[data_off + 13],
        raw[data_off + 14],
        raw[data_off + 15],
        raw[data_off + 16],
    ]);
    let cur_w = u32::from_be_bytes(raw[data_off..data_off + 4].try_into().unwrap());
    let cur_h = u32::from_be_bytes(raw[data_off + 4..data_off + 8].try_into().unwrap());

    // 上界不超过 max_dim，且不小于当前值（篡改只会改小）
    let limit = max_dim.max(cur_w).max(cur_h);
    let mut hits = Vec::new();

    // 常见情形：仅宽度或仅高度被改。先做两条线性扫描，命中即可快速返回。
    for w in 1..=limit {
        if crc_for_dimensions(raw, type_off, w, cur_h) == stored_crc {
            hits.push(IhdrGuess {
                width: w,
                height: cur_h,
            });
        }
    }
    for h in 1..=limit {
        if crc_for_dimensions(raw, type_off, cur_w, h) == stored_crc {
            hits.push(IhdrGuess {
                width: cur_w,
                height: h,
            });
        }
    }
    if !hits.is_empty() {
        hits.sort_by_key(|g| (g.width, g.height));
        hits.dedup();
        return hits;
    }

    // 宽高同时被改：二维遍历（开销 O(n²)，限制 max_dim 防止失控）
    for w in 1..=limit {
        for h in 1..=limit {
            if crc_for_dimensions(raw, type_off, w, h) == stored_crc {
                hits.push(IhdrGuess {
                    width: w,
                    height: h,
                });
            }
        }
    }
    hits
}

/// 用爆破出的尺寸生成修复后的 PNG 字节（仅替换 IHDR 宽高，CRC 保持原样且现已匹配）。
pub fn repaired_png(raw: &[u8], guess: IhdrGuess) -> Option<Vec<u8>> {
    let type_off = locate_ihdr(raw)?;
    let data_off = type_off + 4;
    let mut out = raw.to_vec();
    out[data_off..data_off + 4].copy_from_slice(&guess.width.to_be_bytes());
    out[data_off + 4..data_off + 8].copy_from_slice(&guess.height.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个带正确 CRC 的最小 IHDR 块字节流
    fn make_png_with_ihdr(width: u32, height: u32) -> Vec<u8> {
        let mut raw = vec![
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00,
            0x0D, // IHDR length=13
            b'I', b'H', b'D', b'R',
        ];
        raw.extend_from_slice(&width.to_be_bytes());
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(&[8, 2, 0, 0, 0]); // bitdepth/colortype/...
        let crc = crc32(&raw[12..29]); // 类型+数据
        raw.extend_from_slice(&crc.to_be_bytes());
        raw
    }

    #[test]
    fn recovers_original_width() {
        let original = make_png_with_ihdr(800, 600);
        // 篡改宽度为 100，保留原 CRC
        let mut tampered = original.clone();
        tampered[16..20].copy_from_slice(&100u32.to_be_bytes());
        let hits = brute_force_dimensions(&tampered, 1024);
        assert!(hits.iter().any(|g| g.width == 800 && g.height == 600));
    }

    #[test]
    fn recovers_original_height() {
        let original = make_png_with_ihdr(1024, 768);
        let mut tampered = original.clone();
        tampered[20..24].copy_from_slice(&200u32.to_be_bytes());
        let mut hits = brute_force_dimensions(&tampered, 1024);
        hits.sort_by_key(|g| (g.width, g.height));
        assert!(hits.iter().any(|g| g.width == 1024 && g.height == 768));
    }

    #[test]
    fn repair_roundtrip_restores_bytes() {
        let original = make_png_with_ihdr(640, 480);
        let mut tampered = original.clone();
        tampered[16..20].copy_from_slice(&50u32.to_be_bytes());
        let hits = brute_force_dimensions(&tampered, 1024);
        let guess = hits
            .iter()
            .find(|g| g.width == 640 && g.height == 480)
            .copied()
            .expect("应爆破出原始尺寸");
        let repaired = repaired_png(&tampered, guess).unwrap();
        assert_eq!(repaired, original);
    }

    #[test]
    fn rejects_non_png() {
        assert!(brute_force_dimensions(b"not a png file here", 256).is_empty());
    }

    #[test]
    fn crc32_matches_known_vector() {
        // CRC32("123456789") = 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
