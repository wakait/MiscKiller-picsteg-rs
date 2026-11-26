//! 全文件明文字符串提取（对标 GNU strings / exiftool 的文本发现能力）。
//!
//! 现有 checker 仅在 LSB 提取结果内搜字符串；本模块直接对任意字节缓冲
//! （整文件、imagedata、extradata、雕刻出的嵌入文件）做扫描，
//! 支持 ASCII（含可打印扩展）与 UTF-16LE，并报告偏移，便于 CTF 定位。

/// 一条命中的字符串
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    /// 相对输入缓冲的字节偏移
    pub offset: usize,
    /// 编码方式
    pub encoding: Encoding,
    /// 解码后的文本（控制字符转义前的原始可打印内容）
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

/// 扫描配置
#[derive(Debug, Clone)]
pub struct StringsConfig {
    /// 最小字符串长度（默认 4，贴近 GNU strings）
    pub min_len: usize,
    /// 是否扫描 UTF-16LE（Windows/Office 常见）
    pub utf16: bool,
}

impl Default for StringsConfig {
    fn default() -> Self {
        Self {
            min_len: 4,
            utf16: true,
        }
    }
}

fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t' | b'\r' | b'\n')
}

/// 扫描 ASCII 字符串：连续可打印字节达到 min_len 即命中
fn scan_ascii(data: &[u8], min_len: usize, out: &mut Vec<FoundString>) {
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start {
            if i - s >= min_len {
                let text = String::from_utf8_lossy(&data[s..i]).to_string();
                out.push(FoundString {
                    offset: s,
                    encoding: Encoding::Ascii,
                    text,
                });
            }
            start = None;
        }
    }
    if let Some(s) = start
        && data.len() - s >= min_len
    {
        let text = String::from_utf8_lossy(&data[s..]).to_string();
        out.push(FoundString {
            offset: s,
            encoding: Encoding::Ascii,
            text,
        });
    }
}

/// 扫描 UTF-16LE 字符串：模式为 `可打印字节, 0x00` 交替
fn scan_utf16le(data: &[u8], min_len: usize, out: &mut Vec<FoundString>) {
    let mut start: Option<usize> = None;
    let mut chars: Vec<u8> = Vec::new();
    // 按 2 字节单元成对扫描，单元位置为 (u, u+1)
    let mut u = 0usize;
    while u + 1 < data.len() {
        let lo = data[u];
        let hi = data[u + 1];
        if hi == 0 && is_printable_ascii(lo) {
            if start.is_none() {
                start = Some(u);
                chars.clear();
            }
            chars.push(lo);
        } else if let Some(s) = start.take() {
            if chars.len() >= min_len {
                out.push(FoundString {
                    offset: s,
                    encoding: Encoding::Utf16Le,
                    text: String::from_utf8_lossy(&chars).to_string(),
                });
            }
            chars.clear();
        }
        u += 2;
    }
    if let Some(s) = start
        && chars.len() >= min_len
    {
        out.push(FoundString {
            offset: s,
            encoding: Encoding::Utf16Le,
            text: String::from_utf8_lossy(&chars).to_string(),
        });
    }
}

/// 对任意字节缓冲执行字符串扫描，结果按偏移排序
pub fn scan(data: &[u8], config: &StringsConfig) -> Vec<FoundString> {
    let mut out = Vec::new();
    scan_ascii(data, config.min_len, &mut out);
    if config.utf16 {
        scan_utf16le(data, config.min_len, &mut out);
    }
    out.sort_by_key(|s| s.offset);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_with_offset() {
        let data = b"\x00\x01abcdef\x00gh";
        let hits = scan(data, &StringsConfig::default());
        let ascii: Vec<_> = hits
            .iter()
            .filter(|h| h.encoding == Encoding::Ascii)
            .collect();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].text, "abcdef");
        assert_eq!(ascii[0].offset, 2);
    }

    #[test]
    fn respects_min_len() {
        let data = b"abcdefgh";
        let cfg = StringsConfig {
            min_len: 10,
            utf16: false,
        };
        assert!(scan(data, &cfg).is_empty());
    }

    #[test]
    fn finds_utf16le() {
        // "Hi!" in UTF-16LE，前置两个垃圾字节保证首个单元在偶索引对齐
        let data = [0xFFu8, 0xFE, b'H', 0, b'i', 0, b'!', 0];
        let hits = scan(
            &data,
            &StringsConfig {
                min_len: 3,
                utf16: true,
            },
        );
        let u16: Vec<_> = hits
            .iter()
            .filter(|h| h.encoding == Encoding::Utf16Le)
            .collect();
        assert_eq!(u16.len(), 1);
        assert_eq!(u16[0].text, "Hi!");
        assert_eq!(u16[0].offset, 2);
    }

    #[test]
    fn handles_binary_without_panic() {
        let data = vec![0u8, 255, 1, 128, 13, 10];
        assert!(scan(&data, &StringsConfig::default()).is_empty());
    }
}
