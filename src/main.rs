use clap::{ArgAction, Parser, ValueEnum};
use colored::*;
use std::path::PathBuf;

mod opts;
use opts::{Options, decode_param_string, merge_cli_into_options};
mod carve;
mod checker;
mod crack;
mod extractor;
mod filetype;
mod hexdump;
mod imageio;
mod metadata;
mod pngcrack;
mod result;
mod strings;

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum BitOrder {
    Lsb,
    Msb,
}

#[derive(Parser, Debug)]
#[command(
    name = "misc_killer_picsteg_rs",
    version,
    about = "检测 PNG/BMP 图片中的隐写隐藏数据，并提供 CTF 图片隐写分析能力",
    disable_help_flag = true,
    disable_version_flag = true,
    help_template = "{about}\n\n用法：\n  {usage}\n\n参数：\n{positionals}\n\n选项：\n{options}"
)]
struct Cli {
    /// 显示帮助信息
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    help: Option<bool>,

    /// 显示版本号
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    version: Option<bool>,

    /// 尝试所有已知的扫描方法
    #[arg(short = 'a', long = "all", action = ArgAction::SetTrue)]
    all: bool,

    /// 提取指定载荷，参数示例：'1b,rgb,lsb'
    #[arg(short = 'E', long = "extract")]
    extract: Option<String>,

    /// 像素遍历顺序：ALL、xy、yx、XY、YX、xY、Xy、bY 等（默认自动）
    #[arg(short = 'o', long = "order")]
    order: Option<String>,

    /// 通道（R/G/B/A）或任意组合，多个用逗号分隔
    #[arg(short = 'c', long = "channels")]
    channels: Option<String>,

    /// 使用的位数，如 1、'1,3,5'、区间 '1-8'，也支持掩码 '0x88'
    #[arg(short = 'b', long = "bits")]
    bits: Option<String>,

    /// 最低有效位优先
    #[arg(long = "lsb", action = ArgAction::SetTrue)]
    lsb: bool,

    /// 最高有效位优先
    #[arg(long = "msb", action = ArgAction::SetTrue)]
    msb: bool,

    /// 仅分析/提取质数位置的字节或像素
    #[arg(short = 'P', long = "prime", action = ArgAction::SetTrue)]
    prime: bool,

    /// 在结果前补 N 个零比特
    #[arg(long = "shift")]
    shift: Option<usize>,

    /// 步长
    #[arg(long = "step")]
    step: Option<usize>,

    /// 反转比特（对每字节异或 0xff）
    #[arg(long = "invert", action = ArgAction::SetTrue)]
    invert: bool,

    /// 按像素对齐隐藏数据
    #[arg(long = "pixel-align", action = ArgAction::SetTrue)]
    pixel_align: bool,

    /// 限制检查的字节数，0 表示不限制（默认 256）
    #[arg(short = 'l', long = "limit")]
    limit: Option<usize>,

    /// 启用内置文件类型识别（默认开启，无需系统 file 命令）
    #[arg(long = "file", action = ArgAction::Set, default_value_t = true)]
    file_cmd: bool,

    /// 关闭 ASCII 字符串发现（默认开启）
    #[arg(long = "no-strings", action = ArgAction::SetTrue)]
    no_strings: bool,

    /// 字符串发现模式：first、all、longest、none（默认 first）
    #[arg(short = 's', long = "strings")]
    strings: Option<String>,

    /// 字符串最小长度（默认 8）
    #[arg(short = 'n', long = "min-str-len")]
    min_str_len: Option<usize>,

    /// 详细输出（可重复使用以提升详细度）
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,

    /// 静默警告信息（可重复使用）
    #[arg(short = 'q', long = "quiet", action = ArgAction::Count)]
    quiet: u8,

    /// 强制开启或关闭彩色输出（默认自动）
    #[arg(short = 'C', long = "color")]
    color: Option<bool>,

    /// 输入图片文件名
    input: PathBuf,

    /// 可选的参数字符串快捷方式，如 "2b,b,lsb,xy"
    param_string: Option<String>,

    /// 启用 OpenStego 字典爆破模式
    #[arg(long = "crack", action = ArgAction::SetTrue)]
    crack: bool,

    /// 爆破字典文件，每行一个候选密码（配合 --crack）
    #[arg(long = "wordlist")]
    wordlist: Option<PathBuf>,

    /// 命中后将明文写入该文件（配合 --crack）
    #[arg(long = "crack-out")]
    crack_out: Option<PathBuf>,

    /// 对整个文件原始字节扫描明文字符串（ASCII/UTF-16LE），独立于 LSB 分析
    #[arg(long = "strings-scan", action = ArgAction::SetTrue)]
    strings_scan: bool,

    /// strings 扫描的最小长度（默认 4）
    #[arg(long = "strings-min", default_value_t = 4)]
    strings_min: usize,

    /// 仅输出图片元数据（PNG 文本块 / JPEG EXIF、XMP、COM 注释等）
    #[arg(long = "meta", action = ArgAction::SetTrue)]
    meta: bool,

    /// 爆破 PNG IHDR 真实宽高（CRC32 校验），输出候选尺寸
    #[arg(long = "ihdr-brute", action = ArgAction::SetTrue)]
    ihdr_brute: bool,

    /// 爆破 IHDR 宽高的候选上限（默认 65535）
    #[arg(long = "ihdr-max", default_value_t = 65535)]
    ihdr_max: u32,

    /// 将爆破出的真实尺寸写回并保存修复后的 PNG 到该路径（配合 --ihdr-brute）
    #[arg(long = "fix-ihdr-out")]
    fix_ihdr_out: Option<PathBuf>,

    /// 扫描并报告文件内嵌入/追加的其他文件（foremost/binwalk 类 magic 雕刻）
    #[arg(long = "carve", action = ArgAction::SetTrue)]
    carve: bool,

    /// 将雕刻出的文件导出到该目录（配合 --carve）
    #[arg(long = "carve-out-dir")]
    carve_out_dir: Option<PathBuf>,

    /// 一键 CTF 流水线：元数据→明文→文件雕刻→(PNG)宽高 CRC→LSB 分析
    #[arg(long = "analyze", action = ArgAction::SetTrue)]
    analyze: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(force) = cli.color {
        colored::control::set_override(force);
    }

    // 口令爆破模式：独立于原有检测/提取流程
    if cli.crack {
        return run_crack(&cli);
    }

    // 一键 CTF 流水线（内部有序调用各分析模块）
    if cli.analyze {
        return run_analyze(&cli);
    }

    // 元数据检查模式（exiftool 类）
    if cli.meta {
        return run_meta(&cli);
    }

    // 全文件明文字符串扫描模式（strings 类）
    if cli.strings_scan {
        return run_strings_scan(&cli);
    }

    // PNG IHDR 宽高 CRC 爆破
    if cli.ihdr_brute {
        return run_ihdr_brute(&cli);
    }

    // 通用文件雕刻/分离
    if cli.carve {
        return run_carve(&cli);
    }

    // 解析选项：先默认，再合并 CLI，再合并 param_string（与 Ruby 行为一致：行内覆盖）
    let mut options = Options::default();
    merge_cli_into_options(&mut options, &cli)?;
    if let Some(ps) = &cli.param_string {
        let o2 = decode_param_string(ps)?;
        // 简单字段按优先级覆盖
        if o2.bit_order.is_some() {
            options.bit_order = o2.bit_order;
        }
        if o2.bits.is_some() {
            options.bits = o2.bits;
        }
        if !matches!(o2.order, opts::OrderSpec::Auto) {
            options.order = o2.order;
        }
        if o2.channels.is_some() {
            options.channels = o2.channels;
        }
        if !matches!(o2.pixel_align, opts::PixelAlignSpec::None) {
            options.pixel_align = o2.pixel_align;
        }
        if !matches!(o2.prime, opts::PrimeSpec::None) {
            options.prime = o2.prime;
        }
        if o2.zlib_flag {
            options.zlib_flag = true;
        }
        options.extra_checks &= o2.extra_checks; // 任一侧关闭则关闭
    }

    let img = imageio::Image::load(&cli.input)?;

    if let Some(expr) = &cli.extract {
        // 提取模式：处理特殊名称或解析参数字符串
        use std::io::Write;
        let data = if expr == "imagedata" {
            img.imagedata.clone()
        } else if expr.starts_with("chunk:") {
            // 格式: chunk:N 或 chunk:N:TYPE
            let parts: Vec<&str> = expr.split(':').collect();
            if parts.len() >= 2 {
                let idx: usize = parts[1].parse()?;
                img.chunks
                    .get(idx)
                    .map(|c| c.data.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            // 普通参数字符串，如 "b1,r,lsb,xy"
            let extract_opts = decode_param_string(expr)?;
            let mut final_opts = options.clone();
            if extract_opts.bit_order.is_some() {
                final_opts.bit_order = extract_opts.bit_order;
            }
            if extract_opts.bits.is_some() {
                final_opts.bits = extract_opts.bits;
            }
            if !matches!(extract_opts.order, opts::OrderSpec::Auto) {
                final_opts.order = extract_opts.order;
            }
            if extract_opts.channels.is_some() {
                final_opts.channels = extract_opts.channels;
            }
            if !matches!(extract_opts.prime, opts::PrimeSpec::None) {
                final_opts.prime = extract_opts.prime;
            }

            // 提取模式：如果 limit 是默认值，则使用无限制（与原版行为一致）
            if final_opts.limit == 256 {
                // 默认上限值
                final_opts.limit = 0; // 0 在提取器中表示不限制
            }

            let mut title = String::new();
            extractor::extract(&img, &final_opts, &mut title)
        };

        if options.zlib_flag {
            let mut dec = flate2::read::ZlibDecoder::new(&data[..]);
            let mut out = Vec::new();
            if std::io::Read::read_to_end(&mut dec, &mut out).is_ok() {
                print!("{}", String::from_utf8_lossy(&out));
            } else {
                eprintln!("无法使用 zlib 解压");
            }
        } else {
            std::io::stdout().write_all(&data)?;
        }
        return Ok(());
    }

    // 正常检查模式
    if options.verbose >= 0 {
        println!("{} {}", "[.]".green(), cli.input.display());
    }

    let c = checker::Checker::new(&img, &options);
    let _ = c.check();

    Ok(())
}

/// 执行 OpenStego 字典爆破
fn run_crack(cli: &Cli) -> anyhow::Result<()> {
    let wordlist = cli
        .wordlist
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--crack 模式必须提供 --wordlist <字典文件>"))?;

    // OpenStego 标准载荷固定使用 1b,rgb,lsb,xy
    let mut opts = decode_param_string("1b,rgb,lsb,xy")?;
    opts.limit = 0;

    let img = imageio::Image::load(&cli.input)?;
    let hit = crack::crack_openstego(&img, wordlist, &opts)?;

    match hit {
        Some(hit) => {
            // 若载荷声明压缩，输出解压后的真实文件
            let payload =
                crack::parse_openstego(&extractor::extract(&img, &opts, &mut String::new()));
            let final_bytes = if payload.map(|p| p.compress).unwrap_or(false) {
                use flate2::read::ZlibDecoder;
                use std::io::Read;
                let mut dec = ZlibDecoder::new(&hit.plaintext[..]);
                let mut out = Vec::new();
                if dec.read_to_end(&mut out).is_ok() && !out.is_empty() {
                    out
                } else {
                    hit.plaintext.clone()
                }
            } else {
                hit.plaintext.clone()
            };

            println!(
                "[+] password={:?} AES-{} 明文 {} 字节",
                hit.password,
                hit.key_bits,
                final_bytes.len()
            );

            if let Some(out_path) = &cli.crack_out {
                std::fs::write(out_path, &final_bytes)?;
                println!("[i] 明文已写入 {:?}", out_path);
            } else {
                // 默认打印可打印预览，避免二进制刷屏
                let preview: String = final_bytes
                    .iter()
                    .take(256)
                    .map(|&b| {
                        if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                println!("----- 明文预览 -----");
                println!("{preview}");
            }
            Ok(())
        }
        None => {
            eprintln!("[-] 未找到正确密码");
            std::process::exit(1);
        }
    }
}

/// 元数据检查：输出 PNG 文本块与 JPEG EXIF/XMP/COM 等结构化标签
fn run_meta(cli: &Cli) -> anyhow::Result<()> {
    let raw = std::fs::read(&cli.input)?;
    // 图片可正常解码时拿到 PNG 文本块等结构化信息；解码失败也回退到纯字节扫描
    let tags = match imageio::Image::load(&cli.input) {
        Ok(img) => metadata::collect(&img, &cli.input),
        Err(_) => metadata::collect_from_raw(&raw),
    };
    if tags.is_empty() {
        println!("[-] 未发现可读元数据标签");
        return Ok(());
    }
    println!("[i] 共 {} 条元数据标签：", tags.len());
    for t in &tags {
        println!("  [{:<16}] {:<14} = {}", t.source, t.key, t.value);
    }
    Ok(())
}

/// 全文件明文字符串扫描（对标 strings）
fn run_strings_scan(cli: &Cli) -> anyhow::Result<()> {
    let raw = std::fs::read(&cli.input)?;
    let cfg = strings::StringsConfig {
        min_len: cli.strings_min,
        utf16: true,
    };
    let hits = strings::scan(&raw, &cfg);
    if hits.is_empty() {
        println!("[-] 未发现长度 >= {} 的明文字符串", cli.strings_min);
        return Ok(());
    }
    println!("[i] 共 {} 条字符串：", hits.len());
    for h in &hits {
        let enc = match h.encoding {
            strings::Encoding::Ascii => "ASCII",
            strings::Encoding::Utf16Le => "UTF16",
        };
        // 单行化，避免多行字符串破坏输出对齐
        let line = h.text.replace(['\n', '\r', '\t'], " ");
        println!("  {:>10}  {:<6}  {}", h.offset, enc, line);
    }
    Ok(())
}

/// PNG IHDR 宽高 CRC 爆破，可选写回修复后的 PNG
fn run_ihdr_brute(cli: &Cli) -> anyhow::Result<()> {
    let raw = std::fs::read(&cli.input)?;
    let hits = pngcrack::brute_force_dimensions(&raw, cli.ihdr_max);
    if hits.is_empty() {
        eprintln!("[-] 未能爆破出匹配 CRC 的宽高（非 PNG 或 CRC 本身被破坏）");
        std::process::exit(1);
    }
    println!("[i] 找到 {} 个匹配 CRC32 的尺寸候选：", hits.len());
    for g in &hits {
        println!("  width={}  height={}", g.width, g.height);
    }
    if let Some(out_path) = &cli.fix_ihdr_out {
        // 取第一个候选写回
        let repaired = pngcrack::repaired_png(&raw, hits[0])
            .ok_or_else(|| anyhow::anyhow!("生成修复 PNG 失败"))?;
        std::fs::write(out_path, repaired)?;
        println!("[i] 已将修复后的 PNG 写入 {:?}", out_path);
    }
    Ok(())
}

/// 通用文件雕刻：扫描嵌入/追加文件，可选导出
fn run_carve(cli: &Cli) -> anyhow::Result<()> {
    let raw = std::fs::read(&cli.input)?;
    let hits = carve::scan(&raw);
    if hits.is_empty() {
        println!("[-] 未发现已知签名的嵌入文件");
        return Ok(());
    }
    println!("[i] 发现 {} 个嵌入/追加文件：", hits.len());
    for (i, h) in hits.iter().enumerate() {
        println!(
            "  #{} {:<18} .{:<6} offset={:<10} size={}",
            i, h.kind, h.ext, h.offset, h.size
        );
    }

    if let Some(dir) = &cli.carve_out_dir {
        std::fs::create_dir_all(dir)?;
        let base = cli
            .input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("carved");
        for (i, h) in hits.iter().enumerate() {
            let out = dir.join(format!("{base}_{i:02}_{}.{}", h.offset, h.ext));
            std::fs::write(&out, carve::extract(&raw, h))?;
            println!("[i] 导出 {:?}", out);
        }
    }
    Ok(())
}

/// 一键 CTF 隐写分析流水线，按实战顺序串联各检查器
fn run_analyze(cli: &Cli) -> anyhow::Result<()> {
    let banner = |s: &str| println!("\n{} {s}", "===".green().bold());
    let raw = std::fs::read(&cli.input)?;

    // 1. 元数据检查（exiftool 类）
    banner("[1/5] 元数据检查 (metadata)");
    let meta_tags = match imageio::Image::load(&cli.input) {
        Ok(img) => metadata::collect(&img, &cli.input),
        Err(_) => metadata::collect_from_raw(&raw),
    };
    if meta_tags.is_empty() {
        println!("[-] 无元数据标签");
    } else {
        for t in &meta_tags {
            println!("  [{:<14}] {:<12} = {}", t.source, t.key, t.value);
        }
    }

    // 2. 明文特征提取（strings 类，全文件）
    banner("[2/5] 明文字符串 (strings)");
    let str_hits = strings::scan(
        &raw,
        &strings::StringsConfig {
            min_len: cli.strings_min,
            utf16: true,
        },
    );
    if str_hits.is_empty() {
        println!("[-] 无 >= {} 长度的明文字符串", cli.strings_min);
    } else {
        for h in str_hits.iter().take(50) {
            let line = h.text.replace(['\n', '\r', '\t'], " ");
            println!("  {:>10}  {}", h.offset, line);
        }
        if str_hits.len() > 50 {
            println!("  ...（其余 {} 条省略）", str_hits.len() - 50);
        }
    }

    // 3. 文件分离/雕刻（foremost/binwalk 类）
    banner("[3/5] 文件雕刻 (carve)");
    let carved = carve::scan(&raw);
    if carved.is_empty() {
        println!("[-] 未发现嵌入/追加文件");
    } else {
        for h in &carved {
            println!(
                "  .{:<5} {:<16} offset={} size={}",
                h.ext, h.kind, h.offset, h.size
            );
        }
    }

    // 4. PNG 宽高 CRC 爆破（仅 PNG）
    banner("[4/5] PNG 宽高 CRC 爆破 (IHDR)");
    if raw.starts_with(b"\x89PNG") {
        let dims = pngcrack::brute_force_dimensions(&raw, cli.ihdr_max);
        if dims.is_empty() {
            println!("[-] 未发现 CRC 失配或无法爆破");
        } else {
            for g in &dims {
                println!("  候选尺寸 width={} height={}", g.width, g.height);
            }
        }
    } else {
        println!("[-] 非 PNG，跳过");
    }

    // 5. LSB 隐写分析（zsteg 核心，仅位图类可完整解码）
    banner("[5/5] LSB 隐写分析 (zsteg engine)");
    match imageio::Image::load(&cli.input) {
        Ok(img) => {
            let opts = Options::default();
            let checker = checker::Checker::new(&img, &opts);
            let _ = checker.check();
        }
        Err(e) => println!("[-] 图片无法解码，跳过 LSB 分析：{e}"),
    }

    // F5 / stegpy 等特定算法（JPEG DCT 域）属于 P1 阶段，当前版本占位提示
    println!(
        "\n{} F5/stegpy/outguess/steghide 等 DCT 域算法将在 P1 阶段支持",
        "[i]".yellow()
    );
    Ok(())
}
