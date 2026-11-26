//! 通用文件雕刻/分离（对标 foremost / binwalk 的 magic 签名发现能力）。
//!
//! 现有 imageio 仅硬编码检测 PNG IEND 后的附加数据；本模块用内置签名库
//! 扫描任意字节缓冲（整文件、extradata、LSB 提取结果），报告嵌入文件的
//! 类型、起止偏移与大小，并可切分导出。覆盖 CTF 高频容器与压缩/可执行格式。

/// 一条 magic 签名
struct Signature {
    /// 输出的文件扩展名
    ext: &'static str,
    /// 类型展示名
    kind: &'static str,
    /// 起始魔数
    magic: &'static [u8],
    /// 可选结束标记（含），None 表示延伸到缓冲末尾或下一个签名
    eof: Option<&'static [u8]>,
}

/// 内置签名表（顺序即扫描优先级，常见高频格式在前）
fn signatures() -> Vec<Signature> {
    vec![
        Signature {
            ext: "png",
            kind: "PNG image",
            magic: b"\x89PNG\r\n\x1a\n",
            eof: Some(b"IEND\xAE\x42\x60\x82"), // IEND + 固定 CRC
        },
        Signature {
            ext: "jpg",
            kind: "JPEG image",
            magic: b"\xFF\xD8\xFF",
            eof: Some(b"\xFF\xD9"),
        },
        Signature {
            ext: "gif",
            kind: "GIF image",
            magic: b"GIF8",
            eof: Some(b"\x3B"), // GIF trailer ';'
        },
        Signature {
            ext: "zip",
            kind: "ZIP archive",
            magic: b"PK\x03\x04",
            // EOCD 标记，取其出现位置（不严格解析注释长度）
            eof: Some(b"PK\x05\x06"),
        },
        Signature {
            ext: "rar",
            kind: "RAR archive",
            magic: b"Rar!\x1A\x07",
            eof: None,
        },
        Signature {
            ext: "7z",
            kind: "7-Zip archive",
            magic: b"7z\xBC\xAF\x27\x1C",
            eof: None,
        },
        Signature {
            ext: "gz",
            kind: "gzip stream",
            magic: b"\x1F\x8B\x08",
            eof: None,
        },
        Signature {
            ext: "pdf",
            kind: "PDF document",
            magic: b"%PDF-",
            eof: Some(b"%%EOF"),
        },
        Signature {
            ext: "bmp",
            kind: "BMP image",
            magic: b"BM",
            eof: None,
        },
        Signature {
            ext: "elf",
            kind: "ELF executable",
            magic: b"\x7FELF",
            eof: None,
        },
        Signature {
            ext: "class",
            kind: "Java class",
            magic: b"\xCA\xFE\xBA\xBE",
            eof: None,
        },
        Signature {
            ext: "sqlite",
            kind: "SQLite database",
            magic: b"SQLite format 3\x00",
            eof: None,
        },
        Signature {
            ext: "rtf",
            kind: "RTF document",
            magic: b"{\\rtf",
            eof: None,
        },
    ]
}

/// 一个雕刻命中
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvedFile {
    pub kind: String,
    pub ext: String,
    pub offset: usize,
    pub end: usize,
    pub size: usize,
}

/// 在数据中查找 `needle` 从 `from` 起的下一个位置
fn find_at(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= data.len() {
        return None;
    }
    data[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// 扫描所有嵌入文件。同一偏移只保留首个匹配（签名表优先级最高者）。
pub fn scan(data: &[u8]) -> Vec<CarvedFile> {
    let sigs = signatures();
    let mut hits = Vec::new();
    let mut claimed: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for sig in &sigs {
        let mut search_from = 0;
        while let Some(start) = find_at(data, sig.magic, search_from) {
            search_from = start + 1;
            if !claimed.insert(start) {
                continue; // 该偏移已被更高优先级签名占用
            }
            let end = match sig.eof {
                Some(eof) => match find_at(data, eof, start + sig.magic.len()) {
                    Some(e) => (e + eof.len()).min(data.len()),
                    // 有 EOF 标记但未找到：仍报告，延伸到缓冲末尾
                    None => data.len(),
                },
                None => data.len(),
            };
            hits.push(CarvedFile {
                kind: sig.kind.to_string(),
                ext: sig.ext.to_string(),
                offset: start,
                end,
                size: end.saturating_sub(start),
            });
        }
    }

    hits.sort_by_key(|h| h.offset);
    hits
}

/// 切分指定命中的字节
pub fn extract<'a>(data: &'a [u8], hit: &CarvedFile) -> &'a [u8] {
    &data[hit.offset..hit.end.min(data.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_embedded_zip_with_offset() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(b"some zip body");
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(b"trailer");
        let hits = scan(&data);
        let zip = hits.iter().find(|h| h.ext == "zip").expect("应发现 ZIP");
        assert_eq!(zip.offset, 32);
        assert!(zip.size > 8);
        assert!(data[zip.offset..zip.end].starts_with(b"PK\x03\x04"));
    }

    #[test]
    fn finds_png_with_iend_boundary() {
        let mut data = b"JUNK".to_vec();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(b"ihdr-bytes");
        data.extend_from_slice(b"IEND\xAE\x42\x60\x82");
        data.extend_from_slice(b"AFTER");
        let hits = scan(&data);
        let png = hits.iter().find(|h| h.ext == "png").expect("应发现 PNG");
        assert_eq!(png.offset, 4);
        // 结束边界应恰在 IEND+CRC 之后，不含 AFTER
        assert_eq!(&data[png.end..png.end + 5], b"AFTER");
    }

    #[test]
    fn detects_jpeg_soi_eof() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x01, 0x02, 0xFF, 0xD9, 0xAA];
        let hits = scan(&data);
        let jpg = hits.iter().find(|h| h.ext == "jpg").expect("应发现 JPEG");
        assert_eq!(jpg.offset, 0);
        assert_eq!(jpg.end, 8);
    }

    #[test]
    fn no_false_positive_on_random_bytes() {
        let data = vec![0xABu8; 256];
        assert!(scan(&data).is_empty());
    }

    #[test]
    fn extract_returns_correct_slice() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"%PDF-1.7 body %%EOF");
        let hits = scan(&data);
        let pdf = hits.iter().find(|h| h.ext == "pdf").unwrap();
        let slice = extract(&data, pdf);
        assert!(slice.starts_with(b"%PDF-"));
        assert!(slice.ends_with(b"%%EOF"));
    }
}
