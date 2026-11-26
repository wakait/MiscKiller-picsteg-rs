# MiscKiller-picsteg-rs

[![CI](https://github.com/wakait/MiscKiller-picsteg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/wakait/MiscKiller-picsteg-rs/actions/workflows/ci.yml)
[![Release](https://github.com/wakait/MiscKiller-picsteg-rs/actions/workflows/release.yml/badge.svg)](https://github.com/wakait/MiscKiller-picsteg-rs/actions/workflows/release.yml)

面向 CTF 图片隐写（Misc 方向）的一体化命令行工具，使用 Rust 编写，单文件、零运行时依赖、跨平台。

工具在经典 [zsteg](https://github.com/zed-0xff/zsteg) 的 PNG/BMP 最低有效位（LSB）检测能力之上，进一步集成了明文字符串扫描、元数据检查、文件雕刻、PNG 宽高爆破、加密载荷字典攻击等 CTF 高频考点，目标是用一条命令覆盖图片隐写题的常规排查流程。

> 说明：文中出现的 LSB、CRC、EXIF、AES、magic 等为业界通用技术名词或命令参数，保留英文以避免歧义；其余面向用户的说明均使用中文。

## 功能一览

| 能力 | 对标工具 | 说明 |
|---|---|---|
| LSB 隐写检测 | zsteg | 支持 PNG/BMP，多通道、多位深、多种像素顺序全组合扫描 |
| 明文字符串扫描 | strings | 对整个文件原始字节扫描 ASCII 与 UTF-16LE 字符串并给出偏移 |
| 元数据检查 | exiftool | 解析 PNG 文本块，以及 JPEG 的 EXIF、XMP、Photoshop、COM 注释段 |
| 文件雕刻/分离 | foremost、binwalk | 内置 13 种文件签名，识别追加或嵌套的嵌入文件并可导出 |
| PNG 宽高爆破 | stegsolve | 基于 IHDR 的 CRC32 还原被篡改的真实宽高，并可写回修复 |
| 加密载荷爆破 | stegseek | 针对 OpenStego 载荷进行字典攻击（PBKDF2 + AES） |
| 一键综合分析 | 综合 | 按实战顺序串联上述检查，单命令输出完整结论 |
| 压缩数据识别 | zsteg | 自动识别 zlib 压缩流并尝试解压 |
| 专有格式识别 | zsteg | 识别 OpenStego、wbStego 等工具的特征头 |

## 安装

### 方式一：下载预编译二进制

前往 [发布页面](https://github.com/wakait/MiscKiller-picsteg-rs/releases)，根据操作系统下载对应文件：

- **Linux**：`misc_killer_picsteg_rs-linux-x86_64`
- **macOS（Apple Silicon 芯片）**：`misc_killer_picsteg_rs-macos-aarch64`
- **macOS（Intel 芯片）**：`misc_killer_picsteg_rs-macos-x86_64`
- **Windows**：`misc_killer_picsteg_rs-windows-x86_64.exe`

在 Linux 或 macOS 上，下载后需要添加可执行权限：

```bash
chmod +x misc_killer_picsteg_rs-*
```

### 方式二：从源码构建

需要先安装 Rust 工具链（推荐通过 [rustup](https://rustup.rs/) 安装）：

```bash
cargo build --release
# 构建产物位于 target/release/ 目录
./target/release/misc_killer_picsteg_rs --help
```

## 快速开始

### 一键综合分析（最常用）

对一张图片执行完整排查流水线，依次完成元数据、明文、文件雕刻、PNG 宽高、LSB 五项检查：

```bash
misc_killer_picsteg_rs --analyze 图片.png
```

### LSB 隐写检测

```bash
# 默认检查（自动选择最常见的扫描组合）
misc_killer_picsteg_rs 图片.png

# 尝试所有已知方法（耗时更长，覆盖更全）
misc_killer_picsteg_rs -a 图片.png

# 按指定参数提取载荷，重定向保存为文件
misc_killer_picsteg_rs -E "1b,rgb,lsb,xy" 图片.png > output.bin
```

### 明文字符串扫描

```bash
# 扫描整个文件中的可读字符串（默认最小长度 4）
misc_killer_picsteg_rs --strings-scan 图片.png

# 自定义最小长度为 8
misc_killer_picsteg_rs --strings-scan --strings-min 8 图片.png
```

### 元数据检查

```bash
misc_killer_picsteg_rs --meta 图片.jpg
```

### 文件雕刻与分离

```bash
# 仅报告发现的嵌入文件及其偏移、大小
misc_killer_picsteg_rs --carve 图片.png

# 同时将雕刻出的文件导出到指定目录
misc_killer_picsteg_rs --carve --carve-out-dir ./输出目录 图片.png
```

### PNG 宽高 CRC 爆破

当 PNG 被人为改小宽或高、导致画面显示不完整时使用：

```bash
# 爆破真实宽高并打印候选尺寸
misc_killer_picsteg_rs --ihdr-brute 被篡改.png

# 爆破后直接写回，生成修复后的图片
misc_killer_picsteg_rs --ihdr-brute --fix-ihdr-out 修复后.png 被篡改.png
```

### OpenStego 载荷字典爆破

准备一个每行一个候选密码的字典文件，然后执行：

```bash
misc_killer_picsteg_rs --crack --wordlist 字典.txt 加密图片.png

# 命中后将解密明文写入文件
misc_killer_picsteg_rs --crack --wordlist 字典.txt --crack-out 明文.bin 加密图片.png
```

## 命令参数说明

### 基础检测参数（兼容 zsteg 用法）

| 参数 | 作用 |
|---|---|
| `-a, --all` | 尝试所有已知的扫描方法 |
| `-E, --extract <参数>` | 按指定参数提取载荷，如 `1b,rgb,lsb`；也支持 `imagedata`、`chunk:N` |
| `-o, --order <顺序>` | 像素遍历顺序，如 `xy`、`yx`、`bY` 等 |
| `-c, --channels <通道>` | 通道组合，如 `r`、`rgb`、`bgr` |
| `-b, --bits <位深>` | 使用的位数，如 `1`、`1,3,5`、区间 `1-8` 或掩码 `0x88` |
| `--lsb` / `--msb` | 最低位优先 / 最高位优先 |
| `-P, --prime` | 仅分析质数位置的字节或像素 |
| `--shift <N>` | 在结果前补 N 个零比特 |
| `--invert` | 对每个字节异或 `0xFF` |
| `-l, --limit <N>` | 限制检查的字节数，`0` 表示不限制 |
| `-v, --verbose` | 输出更详细的信息，可重复使用提升详细度 |
| `-q, --quiet` | 抑制警告信息，可重复使用 |

### 本工具扩展参数

| 参数 | 作用 |
|---|---|
| `--analyze` | 一键执行完整分析流水线 |
| `--strings-scan` | 全文件明文字符串扫描 |
| `--strings-min <N>` | 字符串扫描的最小长度，默认 4 |
| `--meta` | 仅输出图片元数据 |
| `--carve` | 启用文件雕刻 |
| `--carve-out-dir <目录>` | 雕刻文件的导出目录 |
| `--ihdr-brute` | 启用 PNG 宽高 CRC 爆破 |
| `--ihdr-max <N>` | 宽高爆破的候选上限，默认 65535 |
| `--fix-ihdr-out <路径>` | 将修复后的 PNG 写入该路径 |
| `--crack` | 启用 OpenStego 字典爆破 |
| `--wordlist <文件>` | 爆破所用字典文件 |
| `--crack-out <路径>` | 将解密得到的明文写入该路径 |

## 支持的图片格式

- **PNG**：完整支持 LSB 分析、文本块元数据、IHDR 爆破、文件雕刻
- **BMP**：完整支持 LSB 分析
- **JPEG/JPG**：支持元数据段扫描（EXIF/XMP/COM 等）；DCT 域算法（steghide、F5、OutGuess 等）规划在后续阶段

## 工作原理简述

- **LSB 检测**：逐像素读取指定颜色通道的最低若干位，按选定顺序重新拼回字节流，再判断其中是否包含文本、压缩数据或已知文件特征。
- **宽高爆破**：PNG 的 IHDR 块自带 CRC32 校验。篡改宽高会使校验失配，工具遍历候选宽高并重算 CRC，找到与文件内校验值一致的组合即为真实尺寸。
- **文件雕刻**：依据各类文件的固定起始魔数（及部分格式的结束标记）在原始字节中定位嵌入文件，不依赖文件扩展名。
- **字典爆破**：OpenStego 使用固定盐值与低迭代次数的 PBKDF2 派生密钥，再以 AES-CBC 加密。工具逐个尝试字典中的密码，通过填充合法性与解压结果判断是否命中。

## 常见问题（FAQ）

**问：Windows 上为什么没有输出文件类型描述？**
答：类型识别会调用系统的 `file` 命令。Windows 默认不自带该命令，此时该子项会静默跳过，不影响字符串提取、LSB 分析等其他功能。可安装 Git for Windows 或 WSL 以获得 `file` 命令。

**问：宽高爆破会不会很慢？**
答：工具会先做宽度、高度两条线性扫描，覆盖绝大多数“只改宽或只改高”的题目，速度很快；仅当两者同时被改时才进入二维遍历，可通过 `--ihdr-max` 限制上限来控制耗时。

**问：字典爆破一定能成功吗？**
答：不能。爆破成功率取决于字典是否包含正确密码。OpenStego 的密钥派生迭代次数很低，因此单条候选的验证开销很小，适合大字典快速尝试。

**问：雕刻出的文件为什么有的延伸到了文件末尾？**
答：像 RAR、7z、ELF 这类格式没有简单可靠的结束标记，工具会将其边界标记为当前数据末尾，属预期行为，可结合偏移与上下文进一步判断。

**问：会修改原始图片吗？**
答：默认所有分析都是只读的。只有显式使用 `--fix-ihdr-out`、`--carve-out-dir`、`--crack-out` 等指定输出路径的参数时，才会写入新文件，不会改动原图。

## 从源码开发

项目使用 GitHub Actions 做持续集成与发布：

- **CI（ci.yml）**：每次推送或合并请求时，在多平台运行格式检查、静态检查、单元测试与构建。
- **发布（release.yml）**：推送版本标签（如 `v1.0.0`）时，自动构建多平台二进制、生成校验和并创建发布。
- **构建闭环（build-loop.yml）**：开发分支推送时触发，使用保留调试符号的 `dev-release` 配置构建，供本地拉取验证。

本地提交前建议先运行门禁检查，确保格式、静态检查与测试全部通过：

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## 许可证

本项目沿用上游 zsteg-rust 的开源协议。详细信息请参阅仓库中的许可证文件。
