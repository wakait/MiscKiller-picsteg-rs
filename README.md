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
| LSB 卡方攻击 | stegdetect | 对 LSB 位平面做 chi-square 统计检验，不依赖明文即可研判 LSB 隐写及嵌入比例 |
| 位平面可视化 | stegsolve | 把各通道 0-7 位平面导出为黑白 PNG，肉眼识别 LSB 噪声、隐藏文字或图案 |
| 明文字符串扫描 | strings | 对整个文件原始字节扫描 ASCII 与 UTF-16LE 字符串并给出偏移 |
| 元数据检查 | exiftool | 解析 PNG 文本块，以及 JPEG 的 EXIF、XMP、Photoshop、COM 注释段 |
| 文件雕刻/分离 | foremost、binwalk | 内置 13 种文件签名，识别追加或嵌套的嵌入文件并可导出 |
| PNG 宽高爆破 | stegsolve | 基于 IHDR 的 CRC32 还原被篡改的真实宽高，并可写回修复 |
| 加密载荷爆破 | stegseek | 针对 OpenStego 载荷进行字典攻击（PBKDF2 + AES） |
| JPEG JSteg 提取 | jsteg | 读取量化 DCT 交流系数的 LSB，确定性提取 JSteg 隐写载荷 |
| JPEG DCT 盲检测 | steghide/F5 分析 | 基于校准攻击的启发式评分，研判 F5/steghide 等对卡方免疫的算法 |
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

## LSB 卡方（chi-square）统计攻击

前述 LSB 检测依赖"提取后是否命中明文/文件特征"，若载荷加密或无明显特征则难以判断是否真有隐写。卡方攻击（Westfeld/Pfitzmann 经典方法）不依赖明文：LSB 顺序嵌入会把随机比特写进像素最低位，使像素值配对 POC（pairs of values，即 (0,1)(2,3)…(254,255)）内两值的频次趋于相等。工具统计 256 个像素值频次，计算卡方量与其上侧概率 p 值——p→1 表示 LSB 接近完全随机（疑似嵌入），p→0 表示自然图像。

为应对"只在图片前段嵌入、后段仍是原始数据"导致全图 p 被稀释的情况，工具还会沿扫描线把像素分块、增量累计直方图，得到 p 值随处理进度上升的曲线，并以曲线峰值与拐点估计嵌入比例。

```bash
# 默认分析 R/G/B 三通道，逐通道输出 p 值、卡方量、自由度与嵌入比例估计
misc_killer_picsteg_rs --chi-square 可疑.png

# 四通道全分析（alpha 恒定时自动跳过并标注）；自定义分块曲线粒度
misc_killer_picsteg_rs --chi-square --chi-channel all --chi-blocks 20 可疑.bmp

# -v 额外打印每通道的分块 p 值曲线（至多 10 个点）
misc_killer_picsteg_rs --chi-square -v 可疑.png
```

输出示例（含 LSB 嵌入的样本）：

```text
chi-square[R]: 疑似 LSB 嵌入 可疑度=100/100 p=1.0000
（chi2=150.915 df=126 嵌入比例估计=5.0%） ［启发式盲检测，非确定性结论，仅供研判］
chi-square[A]: 通道恒定或有效配对不足，跳过
```

结论分三档：p≥0.95 为"疑似 LSB 嵌入"（亮红）、0.5–0.95 为"部分嵌入可疑"（黄色）、<0.5 为"未见显著 LSB 均衡"（灰色）。

> **能力边界**：卡方攻击仅对**顺序、LSB 位平面替换**敏感。对随机/非顺序散布、非 LSB 位（如藏在 bit3）、调色板索引 BMP、极低比例嵌入、以及 F5/steghide 等 JPEG DCT 域算法无效；自然高纹理图也可能偶现高 p，须与 LSB 提取、文件雕刻等结果交叉验证。该功能仅支持 PNG/BMP，JPEG 请使用 `--jpeg-stego`。

## 位平面（bit plane）可视化

卡方攻击给出的是统计概率，而位平面可视化让你**亲眼**检查隐写痕迹（stegsolve 的核心用法）。工具把 R/G/B/A 各通道的 8 个二进制位（bit0=LSB 到 bit7=MSB）分别渲染成一张黑白 PNG：该位为 1 记白、为 0 记黑。自然图像的高位平面连续、接近原图轮廓，低位平面呈细碎噪点；若某个低位平面出现结构化文字、图案或异常规律，往往提示像素域隐写。

```bash
# 导出默认 RGB 三通道的全部 8 个位平面（共 24 张）到指定目录
misc_killer_picsteg_rs --bitplanes --bitplane-out ./位平面 可疑.png

# 四通道全量（含 alpha，共 32 张）；通道选择复用 --chi-channel
misc_killer_picsteg_rs --bitplanes --bitplane-out ./bp --chi-channel all 可疑.png

# 只导 R 通道的 LSB（bit0）；--bp-bits 支持 all、单个 0-7 或逗号列表
misc_killer_picsteg_rs --bitplanes --bitplane-out ./lsb --chi-channel r --bp-bits 0 可疑.bmp
```

导出文件命名为 `{原文件名}_{R|G|B|A}_bit{0..7}.png`，均为 8 位灰度（L8）黑白图，尺寸与原图一致，目录不存在会自动创建。终端会打印导出张数与目录。

> **能力边界**：位平面是**辅助人工研判的可视化材料，不是确定性检测结论**。它只反映像素域位平面，对 JPEG DCT 域算法（F5/steghide/JSteg）、调色板索引隐写（改的是索引而非像素位）不适用；加密或压缩后的载荷可能只呈随机噪点、无可读图案。请结合 LSB 提取与卡方 p 值交叉验证。仅支持 PNG/BMP。

## JPEG DCT 域隐写分析

PNG/BMP 的隐写通常改像素最低位，而 JPEG 的信息承载单位是 8×8 块经过离散余弦变换（DCT）并量化后的系数。本工具提供两类互补的 JPEG 分析能力：**JSteg 确定性提取**与 **F5/steghide 启发式盲检测**，均仅支持 JPEG 输入（按 `FF D8 FF` 魔数校验）。

### JSteg（DCT 域 LSB）提取

JSteg 是最经典的 JPEG 隐写：把秘密比特替换进量化后 DCT **交流（AC）系数**的最低位。工具直接读取量化 DCT 系数（跳过 IDCT 与色彩转换），按标准规则对称提取——跳过每块直流（DC）系数、跳过值为 `0/1/-1` 的 AC 系数，对其余系数取绝对值的最低位，再按「分量 → 块 → 块内 zigzag 索引」顺序、MSB-first 打包成字节。

```bash
# 检测并在终端打印可打印明文预览
misc_killer_picsteg_rs --jsteg 隐写.jpg

# 将提取的原始字节（或长度前缀解析出的明文）写入文件
misc_killer_picsteg_rs --jsteg --jsteg-out payload.bin 隐写.jpg
```

输出示例：

```text
jsteg: 可用 AC 系数=29413 提取比特=29413 打包字节=3676 text: "JSTEG_SECRET_FLAG_2026_CTF_PAYLOAD_OK\t"
```

### F5 / steghide 盲检测（校准攻击）

F5（系数减 1 + 矩阵编码）与 steghide（图论交换保持一阶直方图）都会刻意维持一阶统计，对传统 LSB/卡方（chi-square）检验免疫，无法确定性识别。学术界主流应对是**校准攻击**（Fridrich/Pevný 方法）：把待测 JPEG 解码后裁掉边缘 4 个像素，再用**原图同一张量化表**重压缩，迫使 8×8 网格错位而量化矩阵不变，得到一张近似原始载体的参考图，然后比较两者的 DCT 统计差异。

工具在无训练分类器的前提下，对亮度 AC 系数计算五个维度并做「显著性门控」评分（0–100）：

| 维度 | 含义 | 主要指示 |
|---|---|---|
| 零系数占比偏移 | 待测与校准图零 AC 占比之差 | F5 的系数收缩（zero shrinkage） |
| 一阶直方图 L1 散度 | 系数值分布差异 | 整体统计扰动 |
| 块间共现 L1 散度 | 相邻块同位置系数对的联合分布差异（Fridrich 公式 8） | 块间依赖破坏，对 steghide 敏感 |
| 块间变化相对偏离 | 相邻块同位置系数差的均值变化（公式 5） | 块间依赖破坏 |
| 块效应 B1 相对偏离 | 8 像素块边界的不连续度变化（公式 6） | 重压缩/嵌入痕迹 |

每一维只有越过经验阈值才计分，亚阈值的校准噪声一律记 0，避免多个微小偏差累加成假阳性；综合分映射为「未发现明显异常 / 低度 / 中度 / 高度可疑」，并给出 F5、steghide 或不确定的启发式归因。

```bash
# 终端输出结论、归因、可疑度与关键指标
misc_killer_picsteg_rs --jpeg-stego 可疑.jpg

# 将含全部五维指标的完整文本报告写文件留档
misc_killer_picsteg_rs --jpeg-stego --stego-out 报告.txt 可疑.jpg
```

F5 样本输出示例：

```text
jpeg-dct: 结论=高度可疑 归因=F5 可疑度=99/100
（零占比 0.540 vs 校准 0.492，一阶散度 0.115，块间共现散度 0.164，校准成功） ［启发式盲检测，非确定性结论，仅供研判］
```

干净 JPEG 输出示例：

```text
jpeg-dct: 结论=未发现明显异常 归因=不确定 可疑度=0/100
（零占比 0.219 vs 校准 0.224，一阶散度 0.027，块间共现散度 0.024，校准成功） ［启发式盲检测，非确定性结论，仅供研判］
```

> **能力边界（务必知悉）**：盲检测输出的是**可疑度而非确定结论**，不提取明文、不保证归因准确，阈值为经验值，存在假阳/假阴。特别是高纹理图上的低嵌入率 steghide，其图论交换只改动极少量系数且不增加零，单图启发式在无训练富模型（SRM + SVM/CNN）分类器时可能无法与干净图区分——这是学界公认难点。`--analyze` 流水线在识别到 JPEG 时会自动在 `[6/6]` 步骤同时运行 JSteg 提取与盲检测。

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
| `--jsteg` | 启用 JPEG JSteg（DCT 域 LSB）检测与载荷提取 |
| `--jsteg-out <路径>` | 将 JSteg 提取的原始字节写入该路径 |
| `--jpeg-stego` | 启用 JPEG DCT 域 F5/steghide 启发式盲检测 |
| `--stego-out <路径>` | 将盲检测完整文本报告写入该路径 |
| `--chi-square` | 启用 PNG/BMP 的 LSB 卡方（chi-square）统计攻击 |
| `--chi-channel <通道>` | 卡方分析通道，r/g/b/a 组合或 all，默认 rgb |
| `--chi-blocks <N>` | 卡方分块曲线的块数，默认 20 |
| `--bitplanes` | 启用位平面可视化，导出各通道位平面为黑白 PNG |
| `--bitplane-out <目录>` | 位平面导出目录（配合 --bitplanes，自动创建） |
| `--bp-bits <规格>` | 要导出的位：all、单个 0-7 或逗号列表，默认 all，通道复用 --chi-channel |

## 支持的图片格式

- **PNG**：完整支持 LSB 分析、LSB 卡方攻击、文本块元数据、IHDR 爆破、文件雕刻
- **BMP**：完整支持 LSB 分析与 LSB 卡方攻击
- **JPEG/JPG**：支持元数据段扫描（EXIF/XMP/COM 等）、JSteg（DCT 域 LSB）载荷提取，以及基于校准攻击的 F5/steghide 启发式盲检测

## 工作原理简述

- **LSB 检测**：逐像素读取指定颜色通道的最低若干位，按选定顺序重新拼回字节流，再判断其中是否包含文本、压缩数据或已知文件特征。
- **LSB 卡方攻击**：统计 256 个像素值频次，对 (0,1)(2,3)… 等像素值配对计算卡方量与上侧 p 值；LSB 随机嵌入会使对内频次趋同、p 值趋近 1。再沿扫描线分块累计直方图，用曲线峰值与拐点研判部分嵌入及大致比例。
- **位平面可视化**：逐像素取指定通道的某一二进制位，位为 1 记白（255）、为 0 记黑（0），生成与原图同尺寸的 8 位灰度 PNG；遍历 R/G/B/A × bit0-7 即得全套位平面图，供人工识别低位平面的非自然结构。
- **宽高爆破**：PNG 的 IHDR 块自带 CRC32 校验。篡改宽高会使校验失配，工具遍历候选宽高并重算 CRC，找到与文件内校验值一致的组合即为真实尺寸。
- **文件雕刻**：依据各类文件的固定起始魔数（及部分格式的结束标记）在原始字节中定位嵌入文件，不依赖文件扩展名。
- **字典爆破**：OpenStego 使用固定盐值与低迭代次数的 PBKDF2 派生密钥，再以 AES-CBC 加密。工具逐个尝试字典中的密码，通过填充合法性与解压结果判断是否命中。
- **JSteg 提取**：直接读取量化后的 DCT 系数，跳过 DC 与 `0/1/-1` 的 AC 系数，对其余系数取绝对值最低位，按分量、块、zigzag 顺序还原比特流并打包为字节。
- **DCT 盲检测**：对裁剪后用同一量化表重压缩得到的「校准参考图」，比较其与待测图在零系数占比、直方图、块间共现、块间变化、块效应五个维度的偏离，经显著性门控汇总为 0–100 的可疑度并启发式归因。

## 常见问题（FAQ）

**问：Windows 上为什么没有输出文件类型描述？**
答：类型识别会调用系统的 `file` 命令。Windows 默认不自带该命令，此时该子项会静默跳过，不影响字符串提取、LSB 分析等其他功能。可安装 Git for Windows 或 WSL 以获得 `file` 命令。

**问：宽高爆破会不会很慢？**
答：工具会先做宽度、高度两条线性扫描，覆盖绝大多数“只改宽或只改高”的题目，速度很快；仅当两者同时被改时才进入二维遍历，可通过 `--ihdr-max` 限制上限来控制耗时。

**问：字典爆破一定能成功吗？**
答：不能。爆破成功率取决于字典是否包含正确密码。OpenStego 的密钥派生迭代次数很低，因此单条候选的验证开销很小，适合大字典快速尝试。

**问：雕刻出的文件为什么有的延伸到了文件末尾？**
答：像 RAR、7z、ELF 这类格式没有简单可靠的结束标记，工具会将其边界标记为当前数据末尾，属预期行为，可结合偏移与上下文进一步判断。

**问：`--jpeg-stego` 给出的可疑度能当作确凿证据吗？**
答：不能。它是基于校准攻击的启发式统计评分，输出可疑度与算法倾向（F5/steghide/不确定），并非确定性结论，也不提取明文。F5 的零系数收缩特征较强、检出较可靠；而 steghide 用图论交换保持一阶直方图，在高纹理、低嵌入率场景下可能与干净图难以区分，出现假阴。请结合分值、各维散度与题目上下文综合研判，输出中也固定附带“非确定性结论，仅供研判”的提示。

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
