use colored::Colorize;
use std::fmt;

/// 将字节数组转换为带转义的字符串表示（类似 Ruby 的 inspect）
fn escape_bytes_to_string(data: &[u8]) -> String {
    let mut result = String::from("\"");
    for &b in data {
        match b {
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'\t' => result.push_str("\\t"),
            b'\\' => result.push_str("\\\\"),
            b'"' => result.push_str("\\\""),
            0x07 => result.push_str("\\a"),                 // 响铃符
            0x08 => result.push_str("\\b"),                 // 退格符
            0x0B => result.push_str("\\v"),                 // 垂直制表符
            0x0C => result.push_str("\\f"),                 // 换页符
            0x1B => result.push_str("\\e"),                 // 转义符
            0x20..=0x7e => result.push(b as char),          // 可打印 ASCII
            _ => result.push_str(&format!("\\x{:02X}", b)), // 不可见字符用十六进制表示
        }
    }
    result.push('"');
    result
}

#[derive(Debug, Clone)]
pub enum DetectResult {
    OneChar {
        ch: u8,
        size: usize,
    },
    WholeText(String),
    PartialText {
        text: String,
        offset: usize,
    },
    Zlib {
        data: Vec<u8>,
        offset: usize,
    },
    OpenStego {
        version: u8,
        data_len: u32,
        channel_bits: u8,
        fname_len: u8,
        compress: u8,
        encrypt: u8,
        fname: String,
    },
    WBStego {
        size: u32,
        ext: Option<String>,
        data_preview: Vec<u8>,
        enc: Option<String>,
        even: bool,
    },
    FileType(String),
    /// JPEG JSteg（DCT 域 LSB）提取结果
    Jsteg {
        /// 承载比特的可用交流系数总数（即提取比特数）
        usable_coeffs: usize,
        /// 打包后字节数
        byte_len: usize,
        /// 可打印明文预览（可能为空）
        preview: String,
    },
    /// JPEG DCT 域隐写盲检测结果（F5 / steghide 启发式研判）
    JpegDctStego {
        /// 可疑度中文结论
        verdict: String,
        /// 启发式算法归因（F5 / steghide / 不确定）
        guess: String,
        /// 综合可疑度 0..=100
        score: u8,
        /// 待测图 AC 零值占比
        zero_ratio: f64,
        /// 校准参考图 AC 零值占比
        calib_zero_ratio: f64,
        /// 直方图归一化 L1 散度
        histogram_divergence: f64,
        /// 相邻系数共现矩阵 L1 散度（二阶特征）
        cooccurrence_divergence: f64,
        /// 校准是否成功
        calibrated: bool,
    },
    /// PNG/BMP LSB 卡方（chi-square）攻击结果
    ChiSquareLsb {
        /// 中文结论（疑似 LSB 全嵌入 / 部分嵌入可疑 / 未见显著 LSB 均衡）
        verdict: String,
        /// 通道名（R/G/B/A）
        channel: String,
        /// 卡方上侧 p 值（0~1，越接近 1 越疑似 LSB 嵌入）
        p_value: f64,
        /// 卡方统计量
        chi2: f64,
        /// 自由度
        df: usize,
        /// 嵌入比例估计（p 首次达 0.95 的前缀进度，0 表示未达成）
        embed_ratio: f64,
        /// 可疑度 0..=100
        score: u8,
    },
}

impl fmt::Display for DetectResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectResult::OneChar { ch, size } => {
                // 单字符重复用灰色
                write!(
                    f,
                    "{}",
                    format!("[0x{:02X}] repeated {} times", ch, size).bright_black()
                )
            }
            DetectResult::WholeText(s) => {
                // 整段文本：前缀 "text: " 灰色，内容亮红色
                write!(
                    f,
                    "{}{}",
                    "text: ".bright_black(),
                    format!("{:?}", s).bright_red()
                )
            }
            DetectResult::PartialText { text, offset } => {
                // 部分文本：根据条件决定显示颜色
                let text_repr = format!("{:?}", text);
                let colored_text = if *offset == 0 {
                    // 从数据开头开始 => 亮红色
                    text_repr.bright_red().to_string()
                } else if text.len() > 10
                    && text.contains(' ')
                    && text
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || " .,:!_-\r\n\t".contains(c))
                {
                    // 长文本且包含空格，且是ASCII字符 => 亮红色
                    text_repr.bright_red().to_string()
                } else {
                    // 其他情况不加颜色
                    text_repr
                };
                write!(f, "{}{}", "text: ".bright_black(), colored_text)
            }
            DetectResult::Zlib { data, offset } => {
                // 限制预览大小为100字节（与原版一致）
                const MAX_SHOW_SIZE: usize = 100;
                let preview_data = &data[..data.len().min(MAX_SHOW_SIZE)];

                // 将数据转换为带转义的字符串表示（类似 Ruby 的 inspect）
                let preview = escape_bytes_to_string(preview_data);
                let suffix = if data.len() > MAX_SHOW_SIZE {
                    "..."
                } else {
                    ""
                };

                write!(
                    f,
                    "zlib: data={}{}, offset={}, size={}",
                    preview.bright_red(),
                    suffix,
                    offset,
                    data.len()
                )
            }
            DetectResult::OpenStego {
                version,
                data_len,
                channel_bits,
                fname_len,
                compress,
                encrypt,
                fname,
            } => {
                let summary = format!(
                    "version={} data_len=0x{:x} channel_bits={} fname_len={} compress={} encrypt={} fname={:?}",
                    version, data_len, channel_bits, fname_len, compress, encrypt, fname
                );
                write!(
                    f,
                    "{}",
                    format!("<ZSteg::Result::OpenStego {}", summary).bright_red()
                )
            }
            DetectResult::WBStego {
                size,
                ext,
                data_preview,
                enc,
                even,
            } => {
                let mut parts = vec![format!("size={}", size)];
                if let Some(e) = ext {
                    parts.push(format!("ext={:?}", e));
                }
                // 对原始字节进行转义处理
                let escaped_data = escape_bytes_to_string(data_preview);
                // 转义函数已包含引号，这里无需重复添加
                parts.push(format!("data={}...", escaped_data));
                if *even {
                    parts.push("even=true".to_string());
                }
                if let Some(e) = enc {
                    parts.push(format!("enc={:?}", e));
                }

                let summary = format!("<wbStego {}>", parts.join(", "));
                // 根据是否有有效扩展名决定颜色
                if ext.is_some() && enc.is_none() {
                    write!(f, "{}", summary.bright_red())
                } else {
                    write!(f, "{}", summary.bright_black())
                }
            }
            DetectResult::FileType(desc) => {
                // 内置文件类型识别结果的颜色逻辑（描述为 GNU file 风格英文，含下方关键词）
                let colored_desc = if desc.to_lowercase().contains("dbase 3 data") {
                    // DBase 3 数据类型整体显示为灰色
                    format!("file: {}", desc).bright_black().to_string()
                } else {
                    // 检查是否匹配特定关键词
                    let keywords = ["bitmap", "jpeg", "pdf", "zip", "rar", "7z", "7-z"];
                    let is_highlighted = desc
                        .to_lowercase()
                        .split_whitespace()
                        .any(|word| keywords.iter().any(|kw| word.starts_with(kw)));

                    if is_highlighted {
                        format!("file: {}", desc.bright_red())
                    } else {
                        format!("file: {}", desc.yellow())
                    }
                };
                write!(f, "{}", colored_desc)
            }
            DetectResult::Jsteg {
                usable_coeffs,
                byte_len,
                preview,
            } => {
                // 统计信息灰色，明文预览亮红色（无预览则提示原始字节）
                let header = format!(
                    "jsteg: 可用 AC 系数={} 提取比特={} 打包字节={}",
                    usable_coeffs, usable_coeffs, byte_len
                );
                write!(f, "{}", header.bright_black())?;
                if preview.is_empty() {
                    write!(
                        f,
                        "{}",
                        "（无可打印明文，详见 --jsteg-out 原始字节）".bright_black()
                    )
                } else {
                    write!(f, " {}", format!("text: {:?}", preview).bright_red())
                }
            }
            DetectResult::JpegDctStego {
                verdict,
                guess,
                score,
                zero_ratio,
                calib_zero_ratio,
                histogram_divergence,
                cooccurrence_divergence,
                calibrated,
            } => {
                // 统计指标灰色，高可疑结论亮红
                let header = format!(
                    "jpeg-dct: 结论={} 归因={} 可疑度={}/100",
                    verdict, guess, score
                );
                let stats = format!(
                    "（零占比 {:.3} vs 校准 {:.3}，一阶散度 {:.3}，块间共现散度 {:.3}，校准{}）",
                    zero_ratio,
                    calib_zero_ratio,
                    histogram_divergence,
                    cooccurrence_divergence,
                    if *calibrated { "成功" } else { "不可用" }
                );
                if *score >= 50 {
                    writeln!(f, "{}", header.bright_red())?;
                } else {
                    writeln!(f, "{}", header.yellow())?;
                }
                write!(f, "{}", stats.bright_black())?;
                write!(
                    f,
                    " {}",
                    "［启发式盲检测，非确定性结论，仅供研判］".bright_black()
                )
            }
            DetectResult::ChiSquareLsb {
                verdict,
                channel,
                p_value,
                chi2,
                df,
                embed_ratio,
                score,
            } => {
                let header = format!(
                    "chi-square[{}]: {} 可疑度={}/100 p={:.4}",
                    channel, verdict, score, p_value
                );
                // 按可疑度分级着色：≥95 亮红，≥50 黄色，其余灰色
                if *score >= 95 {
                    writeln!(f, "{}", header.bright_red())?;
                } else if *score >= 50 {
                    writeln!(f, "{}", header.yellow())?;
                } else {
                    writeln!(f, "{}", header.bright_black())?;
                }
                let stats = format!(
                    "（chi2={:.3} df={} 嵌入比例估计={:.1}%）",
                    chi2,
                    df,
                    embed_ratio * 100.0
                );
                write!(f, "{}", stats.bright_black())?;
                write!(
                    f,
                    " {}",
                    "［启发式盲检测，非确定性结论，仅供研判］".bright_black()
                )
            }
        }
    }
}
