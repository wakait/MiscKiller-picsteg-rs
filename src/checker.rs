use crate::hexdump;
use crate::imageio::Image;
use crate::opts::{BitOrder, Options, OrderSpec};
use crate::result::DetectResult;
use colored::Colorize;
use flate2::read::ZlibDecoder;
use std::collections::{HashMap, HashSet};
use std::io::Read;

struct CheckState {
    cache: HashMap<Vec<u8>, String>,
    wastitles: HashSet<String>,
    found_anything: bool,
    need_cr: bool,
    file_enabled: bool,
}

pub struct Checker<'a> {
    pub image: &'a Image,
    pub options: &'a Options,
}

impl<'a> Checker<'a> {
    pub fn new(image: &'a Image, options: &'a Options) -> Self {
        Self { image, options }
    }

    pub fn check(&self) -> Vec<DetectResult> {
        let mut results = Vec::new();
        let mut state = CheckState {
            cache: HashMap::new(),
            wastitles: HashSet::new(),
            found_anything: false,
            need_cr: false,
            file_enabled: self.options.file_cmd,
        };

        // 元数据
        for (k, v) in &self.image.metadata {
            let _r = DetectResult::WholeText(v.clone());
            if self.process_result(
                v.as_bytes(),
                &format!("meta {}", k),
                true,
                &mut state,
                &mut results,
            ) {
                state.found_anything = true;
            }
        }

        // 图像数据：特殊检查时用 limit=0 表示搜索整段数据
        let mut temp_opts = self.options.clone();
        temp_opts.limit = 0; // 搜索整个 imagedata
        let temp_checker = Checker {
            image: self.image,
            options: &temp_opts,
        };
        let result_imagedata = temp_checker.data2result(&self.image.imagedata, &mut state);
        if let Some(r) = result_imagedata
            && !matches!(r, DetectResult::OneChar { .. })
        {
            self.show_title("imagedata", true);
            println!("{}", r);
            results.push(r);
            state.found_anything = true;
        }

        // 附加数据：IEND 结束标记之后的额外数据
        if !self.image.extradata.is_empty() {
            for (idx, extra) in self.image.extradata.iter().enumerate() {
                if !extra.is_empty() {
                    // 显示提示信息
                    if self.options.verbose >= 0 {
                        println!(
                            "{} {} bytes of extra data after image end (IEND)",
                            "[?]".yellow(),
                            extra.len()
                        );
                    }

                    let title = format!("extradata:{}", idx);
                    self.show_title(&title, true);

                    // 显示hexdump（始终显示，因为这是特殊数据）
                    println!("\n{}", hexdump::dump(4, extra, 0));

                    // 也尝试分析内容
                    let temp_checker = Checker {
                        image: self.image,
                        options: &temp_opts,
                    };
                    if let Some(r) = temp_checker.data2result(extra, &mut state)
                        && !matches!(r, DetectResult::OneChar { .. })
                    {
                        println!("{}", r);
                        results.push(r);
                    }

                    state.found_anything = true;
                }
            }
        }

        // 数据块（仅 PNG）
        for (idx, ch) in self.image.chunks.iter().enumerate() {
            if ch.data.len() >= 5 && &ch.ty != b"IDAT" {
                let title = format!(
                    "chunk:{}:{}",
                    idx,
                    std::str::from_utf8(&ch.ty).unwrap_or("????")
                );
                state.need_cr =
                    !self.process_result(&ch.data, &title, true, &mut state, &mut results);
                state.found_anything |= !state.need_cr;
            }
        }

        // 主扫描：按 Ruby check_channels 流程
        let orders: Vec<String> = match &self.options.order {
            OrderSpec::All => {
                if self.image.format == crate::imageio::ImgFormat::Bmp {
                    vec![
                        "bY".into(),
                        "xY".into(),
                        "xy".into(),
                        "yx".into(),
                        "XY".into(),
                        "YX".into(),
                        "Xy".into(),
                        "yX".into(),
                        "Yx".into(),
                    ]
                } else {
                    vec![
                        "xy".into(),
                        "yx".into(),
                        "XY".into(),
                        "YX".into(),
                        "Xy".into(),
                        "yX".into(),
                        "xY".into(),
                        "Yx".into(),
                    ]
                }
            }
            OrderSpec::Auto => {
                if self.image.format == crate::imageio::ImgFormat::Bmp {
                    vec!["bY".into(), "xY".into()]
                } else {
                    vec!["xy".into()]
                }
            }
            OrderSpec::Explicit(v) => v.clone(),
        };
        let bits_list: Vec<u16> = self
            .options
            .bits
            .clone()
            .unwrap_or_else(|| vec![1, 2, 3, 4]);

        for order in orders {
            let prime_vals: Vec<bool> = match self.options.prime {
                crate::opts::PrimeSpec::All => vec![false, true],
                crate::opts::PrimeSpec::Only => vec![true],
                crate::opts::PrimeSpec::None => vec![false],
            };
            for &prime in &prime_vals {
                for &bits in &bits_list {
                    if order.contains('b') || order.contains('B') {
                        // 字节迭代器：不涉及通道
                        self.check_one_combination(&order, prime, bits, &mut state, &mut results);
                    } else {
                        // 像素迭代器：遍历各通道
                        let channels = if let Some(ref chs) = self.options.channels {
                            chs.clone()
                        } else {
                            default_channels()
                        };
                        for ch in &channels {
                            self.check_one_combination_with_channel(
                                &order,
                                prime,
                                bits,
                                ch,
                                &mut state,
                                &mut results,
                            );
                        }
                    }
                }
            }
        }

        if state.found_anything {
            if state.need_cr {
                print!("\r{}\r", " ".repeat(20));
            }
        } else {
            println!("\r[=] nothing :({}", " ".repeat(20));
        }

        results
    }

    fn check_one_combination(
        &self,
        order: &str,
        prime: bool,
        bits: u16,
        state: &mut CheckState,
        results: &mut Vec<DetectResult>,
    ) {
        // 字节迭代器：处理 bY、bX 等顺序
        let bit_orders: Vec<BitOrder> = match self.options.bit_order {
            Some(order) => vec![order],
            None => vec![BitOrder::Lsb, BitOrder::Msb],
        };

        for bo in bit_orders {
            let title = format!(
                "b{},{},{}{}",
                bits,
                match bo {
                    BitOrder::Lsb => "lsb",
                    BitOrder::Msb => "msb",
                },
                order,
                if prime { ",prime" } else { "" }
            );

            // 标题去重
            if state.wastitles.contains(&title) {
                continue;
            }
            state.wastitles.insert(title.clone());

            let mut local = self.options.clone();
            local.order = OrderSpec::Explicit(vec![order.to_string()]);
            local.prime = if prime {
                crate::opts::PrimeSpec::Only
            } else {
                crate::opts::PrimeSpec::None
            };
            local.bits = Some(vec![bits]);
            local.bit_order = Some(bo);
            local.channels = None; // 字节迭代器不使用通道

            let mut _title_out = String::new();
            let data = crate::extractor::extract(self.image, &local, &mut _title_out);

            state.need_cr = !self.process_result(&data, &title, false, state, results);
            state.found_anything |= !state.need_cr;
        }
    }

    fn check_one_combination_with_channel(
        &self,
        order: &str,
        prime: bool,
        bits: u16,
        ch: &str,
        state: &mut CheckState,
        results: &mut Vec<DetectResult>,
    ) {
        // 若未指定 bit_order，则遍历 lsb 和 msb
        let bit_orders: Vec<BitOrder> = match self.options.bit_order {
            Some(order) => vec![order],
            None => vec![BitOrder::Lsb, BitOrder::Msb],
        };

        for bo in bit_orders {
            let title = format!(
                "b{},{},{},{}{}",
                bits,
                ch,
                match bo {
                    BitOrder::Lsb => "lsb",
                    BitOrder::Msb => "msb",
                },
                order,
                if prime { ",prime" } else { "" }
            );

            // 标题去重
            if state.wastitles.contains(&title) {
                continue;
            }
            state.wastitles.insert(title.clone());

            let mut local = self.options.clone();
            local.order = OrderSpec::Explicit(vec![order.to_string()]);
            local.prime = if prime {
                crate::opts::PrimeSpec::Only
            } else {
                crate::opts::PrimeSpec::None
            };
            local.bits = Some(vec![bits]);
            local.bit_order = Some(bo);
            local.channels = Some(vec![ch.to_string()]);

            let mut _title_out = String::new();
            let data = crate::extractor::extract(self.image, &local, &mut _title_out);

            state.need_cr = !self.process_result(&data, &title, false, state, results);
            state.found_anything |= !state.need_cr;
        }
    }

    fn process_result(
        &self,
        data: &[u8],
        title: &str,
        show_title_always: bool,
        state: &mut CheckState,
        results: &mut Vec<DetectResult>,
    ) -> bool {
        // 缓存检查：完整数据去重
        if let Some(cached_title) = state.cache.get(data) {
            if self.options.verbose > 1 {
                self.show_title(title, true);
                println!("[same as {:?}]", cached_title);
                return true;
            } else {
                return false; // 静默跳过重复项
            }
        }

        state.cache.insert(data.to_vec(), title.to_string());

        let result = self.data2result(data, state);

        // 详细度 <= 0：仅当发现非单字符结果时才输出
        if self.options.verbose <= 0 {
            if let Some(ref r) = result
                && !matches!(r, DetectResult::OneChar { .. })
            {
                self.show_title(title, true);
                println!("{}", r);
                results.push(r.clone());
                return true;
            }
            return false;
        }

        // 详细度 > 0：显示所有结果
        if show_title_always || result.is_some() {
            self.show_title(title, true);
        }

        if let Some(r) = result {
            println!("{}", r);
            // 详细模式下额外显示十六进制转储（hexdump）
            if self.options.verbose > 0 {
                println!();
                let dump = hexdump::dump(4, data, self.options.limit);
                print!("{}", dump);
            }
            results.push(r);
            return true;
        }

        if self.options.verbose > 1 {
            println!();
            let dump = hexdump::dump(4, data, self.options.limit);
            print!("{}", dump);
            return true;
        }

        false
    }

    fn show_title(&self, title: &str, _pad: bool) {
        print!("\r{:<20}.. ", title.color("bright black"));
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    fn one_char(data: &[u8]) -> Option<DetectResult> {
        if data.is_empty() {
            return None;
        }
        if data.iter().all(|&b| b == data[0]) {
            return Some(DetectResult::OneChar {
                ch: data[0],
                size: data.len(),
            });
        }
        None
    }

    fn strings_first(data: &[u8], min_len: usize) -> Option<DetectResult> {
        // 在整个数据上搜索字符串（与原版行为一致）
        // limit 参数只影响十六进制转储的显示长度，不限制字符串搜索范围
        let mut start = None;
        for (i, &b) in data.iter().enumerate() {
            let is_print = matches!(b, 0x20..=0x7e | b'\r' | b'\n' | b'\t');
            if is_print {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                if i - s >= min_len {
                    return Some(DetectResult::PartialText {
                        text: String::from_utf8_lossy(&data[s..i]).to_string(),
                        offset: s,
                    });
                } else {
                    start = None;
                }
            }
        }
        // 检查末尾
        if let Some(s) = start
            && data.len() - s >= min_len
        {
            return Some(DetectResult::PartialText {
                text: String::from_utf8_lossy(&data[s..]).to_string(),
                offset: s,
            });
        }
        None
    }

    fn zlib_try(data: &[u8]) -> Option<DetectResult> {
        for offset in 0..data.len().min(256) {
            let slice = &data[offset..];
            let mut dec = ZlibDecoder::new(slice);
            let mut buf = Vec::new();
            if dec.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                return Some(DetectResult::Zlib { data: buf, offset });
            }
        }
        None
    }

    fn whole_text_check(data: &[u8], min_wholetext_len: usize) -> Option<DetectResult> {
        // 检查整个数据是否都是 ASCII 可打印字符（包括 \r, \n, \t）
        if data.len() >= min_wholetext_len
            && data
                .iter()
                .all(|&b| matches!(b, 0x20..=0x7e | b'\r' | b'\n' | b'\t'))
        {
            return Some(DetectResult::WholeText(
                String::from_utf8_lossy(data).to_string(),
            ));
        }
        None
    }

    fn data2result(&self, data: &[u8], state: &mut CheckState) -> Option<DetectResult> {
        if let Some(r) = Self::one_char(data) {
            return Some(r);
        }

        // OpenStego 特征检测
        if let Some(r) = Self::check_openstego(data) {
            return Some(r);
        }

        // WBStego 检测（仅在特定条件下触发）
        if self.options.bit_order == Some(crate::opts::BitOrder::Lsb)
            && let Some(r) =
                Self::check_wbstego(data, self.image.format == crate::imageio::ImgFormat::Bmp)
        {
            return Some(r);
        }

        // 整段文本检查应先于内置文件类型识别，采用更小的最小长度（min_str_len - 2）
        let min_wholetext_len = self.options.min_str_len.saturating_sub(2);
        if let Some(r) = Self::whole_text_check(data, min_wholetext_len) {
            return Some(r);
        }
        if state.file_enabled
            && let Some(desc) = crate::filetype::detect(data)
        {
            return Some(DetectResult::FileType(desc));
        }
        if let Some(r) = Checker::zlib_try(data) {
            return Some(r);
        }
        // 字符串搜索在整个数据上进行
        if let Some(r) = Self::strings_first(data, self.options.min_str_len) {
            return Some(r);
        }
        None
    }

    fn check_wbstego(data: &[u8], _is_bmp: bool) -> Option<DetectResult> {
        // WBStego 文件格式检测
        if data.len() < 4 {
            return None;
        }

        // 读取前3字节作为大小（little-endian）
        let size1 = u32::from_le_bytes([data[0], data[1], data[2], 0]);

        // 基本有效性检查
        if size1 == 0 || size1 > 1_000_000 {
            return None;
        }

        // 检查过多零字节（防止误报）
        if data.len() > 3 {
            let zero_count = data[3..].iter().filter(|&&b| b == 0).count();
            if zero_count > 10 && data.len() - 3 - zero_count < 4 {
                return None;
            }
        }

        if data.len() < 6 {
            return None;
        }

        // 读取扩展名（3字节）
        let ext_bytes = &data[3..6];

        // 检查是否是 wbStego 4.x 加密头
        if ext_bytes[0] == 0x00 && ext_bytes[1] == 0xff {
            let hdr_len = ext_bytes[2] as usize;
            if data.len() > 6 + hdr_len {
                let enc_type = if hdr_len > 0 { data[6] } else { 0 };
                let enc = match enc_type {
                    1 => Some("Blowfish".to_string()),
                    2 => Some("Twofish".to_string()),
                    3 => Some("CAST128".to_string()),
                    4 => Some("Rijndael".to_string()),
                    _ => Some(format!("unknown #{}", enc_type)),
                };
                let data_start = 6 + hdr_len;
                // 增加预览长度到30字节
                let preview_end = (data_start + 30).min(data.len());
                let preview = data[data_start..preview_end].to_vec();
                return Some(DetectResult::WBStego {
                    size: size1,
                    ext: None,
                    data_preview: preview,
                    enc,
                    even: false,
                });
            }
        }

        // 检查是否是 wbStego 2.x/3.x controlbyte
        let controlbyte = ext_bytes[0];
        if (controlbyte & 0xc0) != 0 {
            let enc = if (controlbyte & 0x80) != 0 {
                Some("wbStego 2.x/3.x".to_string())
            } else {
                None
            };
            // 增加预览长度到30字节
            let preview_end = (4 + 30).min(data.len());
            let data_preview = data[4..preview_end].to_vec();
            return Some(DetectResult::WBStego {
                size: size1,
                ext: None,
                data_preview,
                enc,
                even: false,
            });
        }

        // 检查扩展名是否有效（7-bit ASCII，无通配符）
        let ext_str = String::from_utf8_lossy(ext_bytes);
        let is_valid_ext = ext_bytes.iter().all(|&b| (0x20..=0x7e).contains(&b))
            && !ext_str.contains('*')
            && !ext_str.contains('?');

        if is_valid_ext {
            // 增加预览长度到30字节
            let preview_end = (6 + 30).min(data.len());
            let data_preview = data[6..preview_end].to_vec();
            return Some(DetectResult::WBStego {
                size: size1,
                ext: Some(ext_str.to_string()),
                data_preview,
                enc: None,
                even: false,
            });
        }

        None
    }

    fn check_openstego(data: &[u8]) -> Option<DetectResult> {
        // 搜索 "OPENSTEGO" 字符串
        const MAGIC: &[u8] = b"OPENSTEGO";
        let pos = data.windows(MAGIC.len()).position(|w| w == MAGIC)?;

        // 从 "OPENSTEGO" 后面读取头部信息
        let header_start = pos + MAGIC.len();
        if data.len() < header_start + 8 {
            return None; // 数据不够
        }

        let version = data[header_start];
        let data_len = u32::from_le_bytes([
            data[header_start + 1],
            data[header_start + 2],
            data[header_start + 3],
            data[header_start + 4],
        ]);
        let channel_bits = data[header_start + 5];
        let fname_len = data[header_start + 6];
        let compress = data[header_start + 7];

        if data.len() < header_start + 8 + 1 {
            return None;
        }
        let encrypt = data[header_start + 8];

        // 读取文件名
        let fname_start = header_start + 9;
        let fname = if fname_len > 0 && data.len() >= fname_start + fname_len as usize {
            String::from_utf8_lossy(&data[fname_start..fname_start + fname_len as usize])
                .to_string()
        } else {
            String::new()
        };

        Some(DetectResult::OpenStego {
            version,
            data_len,
            channel_bits,
            fname_len,
            compress,
            encrypt,
            fname,
        })
    }
}

fn default_channels() -> Vec<String> {
    vec![
        "r".into(),
        "g".into(),
        "b".into(),
        "rgb".into(),
        "bgr".into(),
    ]
}
