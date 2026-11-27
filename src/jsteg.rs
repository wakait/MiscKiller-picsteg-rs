//! JPEG JSteg（DCT 域 LSB）隐写检测与载荷提取。
//!
//! JSteg 是最经典的 JPEG 隐写：把秘密比特替换进**量化后 DCT 交流系数**的最低位。
//! 本模块借助纯 Rust 的 `libjpeg-turbo-rs` 直接读取量化 DCT 系数（跳过 IDCT 与
//! 色彩转换），按 JSteg 标准规则对称提取：
//! 1. 跳过每个 8x8 块的直流系数（block[0]）；
//! 2. 跳过值为 0 / 1 / -1 的交流系数（这些值在 JPEG 熵编码中不可承载替换比特）；
//! 3. 对其余交流系数取绝对值的最低位；
//! 4. 按 分量 → 块 → 块内 zigzag 索引 的顺序拼出比特流，再按 MSB-first 打包成字节。

use libjpeg_turbo_rs::{ComponentCoefficients, read_coefficients};

/// JSteg 提取结果：除原始字节外，附带统计信息与解析出的明文预览。
#[derive(Debug, Clone)]
pub struct JstegPayload {
    /// 承载比特的可用交流系数总数（即提取出的比特数）
    pub usable_coeffs: usize,
    /// MSB-first 打包后的原始字节
    pub bytes: Vec<u8>,
}

/// 单个量化 DCT 系数到 JSteg 比特的纯函数映射。
///
/// 直流规则在外层跳过；这里只处理交流系数：0/1/-1 不可承载返回 `None`，
/// 其余返回绝对值的最低位。对负系数取绝对值的 LSB，与主流 JSteg 实现一致。
fn coef_to_bit(c: i16) -> Option<u8> {
    match c {
        -1..=1 => None,
        other => Some((other.unsigned_abs() & 1) as u8),
    }
}

/// 遍历单个分量的全部块，收集可用交流系数的 LSB。
fn collect_component(component: &ComponentCoefficients, out: &mut Vec<u8>) {
    for block in &component.blocks {
        // block[0] 为直流系数，跳过；block[1..64] 为 zigzag 顺序的交流系数
        for &coef in &block[1..64] {
            if let Some(bit) = coef_to_bit(coef) {
                out.push(bit);
            }
        }
    }
}

/// 从 JPEG 原始字节提取 JSteg 比特流并打包为字节。
pub fn extract(jpeg: &[u8]) -> anyhow::Result<JstegPayload> {
    let coefficients =
        read_coefficients(jpeg).map_err(|e| anyhow::anyhow!("解析 JPEG DCT 系数失败：{e}"))?;

    let mut bits: Vec<u8> = Vec::new();
    for component in &coefficients.components {
        collect_component(component, &mut bits);
    }

    let usable_coeffs = bits.len();
    let bytes = pack_bytes(&bits);
    Ok(JstegPayload {
        usable_coeffs,
        bytes,
    })
}

/// 把 0/1 比特流按 MSB-first（每字节高位在前）打包；不足 8 位的尾部丢弃。
fn pack_bytes(bits: &[u8]) -> Vec<u8> {
    let (chunks, _remainder) = bits.as_chunks::<8>();
    let mut out = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit != 0 {
                byte |= 1 << (7 - i);
            }
        }
        out.push(byte);
    }
    out
}

/// 尝试按常见长度前缀解析载荷，返回截断后的明文负载；无法识别则返回 `None`。
///
/// 覆盖 JSteg 工具常见的两种 4 字节前缀（大端/小端），长度字段须落在合理区间
/// （大于 0 且不超过剩余字节）才采信，避免随机数据误判。
pub fn parse_length_prefixed(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let body_len = data.len() - 4;

    let try_len = |len: usize| -> Option<Vec<u8>> {
        if len > 0 && len <= body_len {
            Some(data[4..4 + len].to_vec())
        } else {
            None
        }
    };

    // 优先大端（网络字节序，多数隐写工具采用），再试小端
    try_len(be).or_else(|| try_len(le))
}

/// 提取字节缓冲开头的可打印 ASCII 文本预览，遇首个不可打印字节停止，
/// 用于在无长度前缀时直接呈现可能的明文。返回清洗后的字符串（控制字符转义）。
pub fn printable_preview(data: &[u8], max_len: usize) -> String {
    let mut s = String::new();
    for &b in data {
        if s.len() >= max_len {
            break;
        }
        match b {
            0x20..=0x7e | b'\t' | b'\r' | b'\n' => s.push(b as char),
            _ => break,
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coef_to_bit_skips_dc_unusable_values() {
        // 0 / 1 / -1 不可承载
        assert_eq!(coef_to_bit(0), None);
        assert_eq!(coef_to_bit(1), None);
        assert_eq!(coef_to_bit(-1), None);
        // 正系数取 LSB
        assert_eq!(coef_to_bit(2), Some(0));
        assert_eq!(coef_to_bit(3), Some(1));
        assert_eq!(coef_to_bit(100), Some(0));
        assert_eq!(coef_to_bit(101), Some(1));
    }

    #[test]
    fn coef_to_bit_uses_absolute_value_for_negative() {
        // 负系数取绝对值的 LSB：|-2|=2->0, |-3|=3->1, |-101|=101->1
        assert_eq!(coef_to_bit(-2), Some(0));
        assert_eq!(coef_to_bit(-3), Some(1));
        assert_eq!(coef_to_bit(-101), Some(1));
    }

    #[test]
    fn pack_bytes_msb_first() {
        // 0b10110000 = 0xB0，0b11111111 = 0xFF
        let bits = vec![1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(pack_bytes(&bits), vec![0xB0, 0xFF]);
    }

    #[test]
    fn pack_bytes_drops_trailing_under_byte() {
        // 9 个比特，最后 1 个不足一字节应丢弃
        let bits = vec![1, 0, 1, 1, 0, 0, 0, 0, 1];
        assert_eq!(pack_bytes(&bits), vec![0xB0]);
    }

    #[test]
    fn parse_big_endian_length_prefix() {
        // 大端长度=5，负载 "hello"
        let mut data = vec![0u8, 0u8, 0u8, 5u8];
        data.extend_from_slice(b"hello");
        data.extend_from_slice(b"TAIL");
        assert_eq!(parse_length_prefixed(&data), Some(b"hello".to_vec()));
    }

    #[test]
    fn parse_little_endian_length_prefix() {
        // 小端长度=3，负载 "abc"
        let mut data = vec![3u8, 0u8, 0u8, 0u8];
        data.extend_from_slice(b"abc");
        assert_eq!(parse_length_prefixed(&data), Some(b"abc".to_vec()));
    }

    #[test]
    fn parse_rejects_implausible_length() {
        // 声明长度远超剩余字节，两种端序都不应采信
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, b'x', b'y'];
        assert_eq!(parse_length_prefixed(&data), None);
    }

    #[test]
    fn printable_preview_stops_at_first_binary() {
        let data = b"hello\x00world";
        assert_eq!(printable_preview(data, 64), "hello");
    }

    #[test]
    fn printable_preview_respects_max_len() {
        let data = b"abcdefghij";
        assert_eq!(printable_preview(data, 4), "abcd");
    }
}
