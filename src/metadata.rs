//! 图片元数据检查（对标 exiftool 的结构化标签发现）。
//!
//! - PNG：复用 imageio 已解析的 tEXt/iTXt/zTXt 文本块
//! - JPEG：手工扫描标记段，识别 JFIF、EXIF(APP1)、XMP(APP1)、Photoshop IRB(APP13)、COM 注释
//!
//! 不依赖重型 EXIF 解析库；CTF 关注"有无敏感字段/软件痕迹/隐藏注释"，
//! 因此输出段类型、原始可读文本与偏移，兼顾检出率与零额外依赖。

use crate::imageio::Image;
use std::path::Path;

/// 一条元数据标签
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaTag {
    /// 来源格式与段，例如 "JPEG/APP1-EXIF"、"PNG/tEXt"
    pub source: String,
    /// 键名（PNG 关键字、JPEG 段名；无键时为空）
    pub key: String,
    /// 可读值（二进制做 lossy 转换）
    pub value: String,
}

const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];

fn printable_preview(data: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&data[..data.len().min(max)])
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

/// 扫描 JPEG 标记段，提取元数据相关 APP/COM 信息
fn scan_jpeg(raw: &[u8]) -> Vec<MetaTag> {
    let mut tags = Vec::new();
    if raw.len() < 4 || raw[0..2] != JPEG_SOI {
        return tags;
    }
    let mut i = 2;
    while i + 4 <= raw.len() {
        if raw[i] != 0xFF {
            // 扫描数据区或对齐填充，前进直到下一个标记
            i += 1;
            continue;
        }
        // 跳过连续 0xFF 填充
        while i < raw.len() && raw[i] == 0xFF {
            i += 1;
        }
        if i >= raw.len() {
            break;
        }
        let marker = raw[i];
        i += 1;

        // SOS 之后是熵编码数据，元数据扫描到此结束
        if marker == 0xDA {
            break;
        }
        // 无长度字段的独立标记（RSTn、SOI、EOI、TEM）
        if marker == 0x01 || (0xD0..=0xD9).contains(&marker) {
            continue;
        }
        if i + 2 > raw.len() {
            break;
        }
        let seg_len = u16::from_be_bytes([raw[i], raw[i + 1]]) as usize;
        if seg_len < 2 || i + seg_len > raw.len() {
            break;
        }
        let payload = &raw[i + 2..i + seg_len];

        match marker {
            0xE0 => tags.push(MetaTag {
                source: "JPEG/APP0".into(),
                key: "JFIF".into(),
                value: printable_preview(payload, 64),
            }),
            0xE1 => {
                if payload.starts_with(b"Exif\0\0") {
                    tags.push(MetaTag {
                        source: "JPEG/APP1".into(),
                        key: "EXIF".into(),
                        value: printable_preview(&payload[6..], 128),
                    });
                } else if payload.starts_with(b"http://ns.adobe.com/xap/1.0/")
                    || payload
                        .windows(31)
                        .any(|w| w == b"http://ns.adobe.com/xap/1.0/")
                {
                    tags.push(MetaTag {
                        source: "JPEG/APP1".into(),
                        key: "XMP".into(),
                        value: printable_preview(payload, 256),
                    });
                } else {
                    tags.push(MetaTag {
                        source: "JPEG/APP1".into(),
                        key: "APP1".into(),
                        value: printable_preview(payload, 64),
                    });
                }
            }
            0xED => tags.push(MetaTag {
                source: "JPEG/APP13".into(),
                key: "Photoshop-IRB".into(),
                value: printable_preview(payload, 128),
            }),
            0xFE => tags.push(MetaTag {
                source: "JPEG/COM".into(),
                key: "Comment".into(),
                value: printable_preview(payload, 256),
            }),
            _ => {}
        }
        i += seg_len;
    }
    tags
}

/// 汇总图片全部可读元数据
pub fn collect(image: &Image, raw_path: &Path) -> Vec<MetaTag> {
    let mut tags = Vec::new();

    // PNG 文本块（imageio 已解析 keyword -> value）
    let mut keys: Vec<&String> = image.metadata.keys().collect();
    keys.sort();
    for k in keys {
        if let Some(v) = image.metadata.get(k) {
            tags.push(MetaTag {
                source: "PNG/text".into(),
                key: k.clone(),
                value: v.clone(),
            });
        }
    }

    // JPEG：直接读原始文件扫描标记段
    if image.format == crate::imageio::ImgFormat::Bmp {
        return tags;
    }
    if let Ok(raw) = std::fs::read(raw_path) {
        tags.extend(collect_from_raw(&raw));
    }
    tags
}

/// 仅基于原始字节提取元数据（无需 image crate 成功解码），
/// 用于图片损坏/截断但仍需扫描 EXIF、注释等场景。
pub fn collect_from_raw(raw: &[u8]) -> Vec<MetaTag> {
    let mut tags = Vec::new();
    if raw.len() >= 3 && raw[0..2] == JPEG_SOI {
        tags.extend(scan_jpeg(raw));
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_jpeg_comment_and_app0() {
        // 构造最小 JPEG 结构：SOI + APP0(段) + COM(段) + SOS 占位
        let mut jpeg = vec![0xFF, 0xD8];
        // APP0: marker + len(2) + "JFIF\0..."
        let app0 = b"JFIF\0abc";
        jpeg.push(0xFF);
        jpeg.push(0xE0);
        jpeg.extend_from_slice(&((app0.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(app0);
        // COM
        let com = b"secret comment";
        jpeg.push(0xFF);
        jpeg.push(0xFE);
        jpeg.extend_from_slice(&((com.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(com);
        // SOS 终止元数据扫描
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);

        let tags = scan_jpeg(&jpeg);
        assert!(tags.iter().any(|t| t.key == "JFIF"));
        let comment = tags
            .iter()
            .find(|t| t.key == "Comment")
            .expect("应有 COM 注释");
        assert_eq!(comment.value, "secret comment");
    }

    #[test]
    fn detects_exif_marker() {
        let mut jpeg = vec![0xFF, 0xD8];
        let exif = b"Exif\0\0MM\x00*";
        jpeg.push(0xFF);
        jpeg.push(0xE1);
        jpeg.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(exif);
        jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);

        let tags = scan_jpeg(&jpeg);
        assert!(tags.iter().any(|t| t.key == "EXIF"));
    }

    #[test]
    fn rejects_non_jpeg() {
        assert!(scan_jpeg(b"not a jpeg at all").is_empty());
    }
}
