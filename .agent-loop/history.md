# Agent Loop 迭代历史 —— MiscKiller-picsteg-rs (misc_killer_picsteg_rs)

> 闭环工作流：本地 precheck → 推送监控 watch → 拉取产物 fetch_run → 根因分析 → 决策。
> 熔断规则：单次指令最多自主执行 3 轮完整云端构建循环。
> 分支：所有循环提交仅在 `dev` / `agent/**` 上进行，禁止直接推送 main/master。

## 项目背景

- 现状：Ruby zsteg 的 Rust 重写，仅覆盖 PNG/BMP 的 LSB 隐写检测，零单元测试、零爆破能力。
- 本轮目标（用户选定）：**阶段 3 口令爆破优先** —— 让 camouflage / openstego / wbstego 等加密样本可字典攻击出明文。
- 平台矩阵：windows-x86_64-msvc、linux-x86_64-musl、macos-x86_64、macos-aarch64（不含 linux aarch64）。

## Iteration 记录

### Iteration #0 - 脚手架初始化（2026-11-26）
- **Commit**: 未提交（工作区改动）
- **改动要点**:
  - 从 master 切出 `agent/pass-crack` 分支
  - Cargo.toml 新增 `[profile.dev-release]`（inherits release，debug=true 保留行号，lto=false 加速）
  - 新增 `.github/workflows/build-loop.yml` 与 `templates/build-loop.yml`（4 平台 dev-release 构建 + 产物上传）
  - 新增 `loop_driver.sh`（precheck/watch/fetch_run；WSL 下自动探测 Windows cargo.exe）
  - 新增本历史文件
- **CI 状态**: 尚未推送
- **本地运行结果**: precheck 退出码 0（fmt/clippy -D warnings/dev-release build/test 全过），产物 target/dev-release/zsteg-rust.exe (1.7MB)
- **根因诊断**:
  1. WSL 的 /usr/bin/cargo 是 apt 独立版（无 rustup/rustfmt/clippy），脚本改为探测 /mnt/c/Users/*/.cargo/bin/cargo.exe
  2. 存量代码从未真正通过 CI 的 clippy -D warnings：24 个 lint，经 cargo clippy --fix + 手动修复 5 个（dead_code/unnecessary_unwrap×2/too_many_arguments/删 Zlib 死字段 size）清零
  3. 清理 4 个未用依赖 thiserror/png/regex/byteorder
- **冒烟验证**: flower_rgb3(SuperSecretMessage)、openstego_send(OpenStego encrypt=1)、extradata(foobar3)、wbsteg_noenc 均正确识别，重构零退化
- **下一步行动**: 调研 camouflage/openstego/wbstego 加密格式，产出口令爆破实现计划

### Iteration #1 - 加密格式调研（2026-11-26，未推送，纯本地调研）
- **Commit**: 未提交
- **改动要点**: 无代码改动；Web 调研 + 样本字节级验证
- **CI 状态**: 不适用
- **本地运行结果**: 成功提取 openstego_send.png 的 OPENSTEGO 载荷（73728 字节，头 `4F 50 45 4E 53 54 45 47 4F`）
- **根因诊断（三类目标加密机制）**:
  1. **Camouflage（无需爆破，弱编码可直接还原）**: 数据在 IEND 后；固定静态 key XOR（key.py 20MB，循环重复）；密码/文件名经 XOR 后以 0x20 截断，存于 craw 固定负偏移（密码 -275、secret 名 -795、carrier 名 -540、版本 -20、隐藏大小 -285、起始位置 -281）；魔数 `00 00 .. .. d9 01` 或 `20 00 .. .. c3 01`。
  2. **OpenStego（真正可字典爆破，首选目标）**: 算法 PBEWithHmacSHA256AndAES_128/256；**硬编码 8 字节 SALT=285F71C91E350A62，迭代仅 7 次**（PBKDF2-HMAC-SHA256）；载荷布局 = OPENSTEGO 魔数 + 头(version/data_len/channel_bits/fname_len/compress/encrypt/fname) + 加密体[1字节参数长度+AES参数+AES/CBC密文+PKCS5Padding]。错误密码抛 BadPaddingException → Rust 侧用 PKCS7 padding 合法性 + 解压校验作为命中判据。7 轮迭代使每候选开销极低，适合大字典。
  3. **wbStego（成本最高，暂缓）**: Delphi 闭源，4.x 用 Blowfish/Twofish/CAST128/Rijndael，密钥派生无公开规范，当前加密样本连 LSB 提取都 `nothing`，需先修检测再逆向 KDF。
- **下一步行动**: 优先落地 OpenStego 字典爆破（新增 crack 子命令 + pbkdf2/aes 依赖），Camouflage 作为"直接还原"模块紧随其后，wbStego 暂缓

### Iteration #2 - OpenStego 字典爆破实现（2026-11-26，本地完成未推送）
- **Commit**: 未提交
- **改动要点**:
  - 新增 `src/crack.rs`：OPENSTEGO 载荷解析、PBKDF2-HMAC-SHA256(salt 固定、7 轮)、AES-128/256-CBC、从 JCE ASN.1 参数提取 IV、PKCS7 padding 命中判据 + zlib 解压强校验
  - CLI 新增 `--crack --wordlist <文件> [--crack-out <明文>]`（顶层标志，未用子命令以兼容原位置参数）
  - 依赖新增 pbkdf2(simple)/hmac/sha2/aes/cbc/cipher
  - 4 个单元测试：正确密码命中、错误密码拒绝、IV 提取、头部解析
  - .gitignore 增加 .local-logs/
- **CI 状态**: 尚未推送（推送权限待解：对源仓 jiayuqi7813/zsteg-rust 仅 pull）
- **本地运行结果**: precheck 退出码 0；4/4 测试通过；openstego_send.png 端到端跑通（21 个常见密码未命中属正常，真实密码未知），错误密码被可靠拒绝
- **根因诊断**:
  1. pbkdf2 0.12 关 default-features 后 pbkdf2_hmac 不可用 → 启用 simple 特性
  2. AES 密钥不能 `Vec.into()` 转 GenericArray → new_from_slices
  3. cipher 0.4 encrypt_padded_mut 签名为 (buffer, pos)，数据须预写入 buffer
  4. clap 子命令与顶层位置参数 input 冲突 → 改顶层标志
- **下一步行动**: 解决远程仓库重组（新建 wakait/MiscKiller-picsteg-rs），随后进入 P0 功能（PNG 宽高爆破/文件雕刻/EXIF）

### Iteration #3 - 仓库重组 + 云端闭环打通（2026-11-26）
- **Commit**: 429d352（rebrand+crack）、f84163e（gh 探测+macos runner）
- **改动要点**:
  - crate 重命名 misc_killer_picsteg_rs；新建 Public 组织仓 wakait/MiscKiller-picsteg-rs；origin 重指，彻底移除 jiayuqi7813 上游及所有跟踪 ref；清 .git/config 残留；全仓旧名替换（README/CI/release/build-loop/模板/环境说明）
  - loop_driver.sh 增加 gh.exe 探测（Program Files 带空格）、WSL 平台识别路由 Windows 产物、wslpath 路径转换、PowerShell Start-Process 超时执行
  - build-loop macos runner 修正：x86_64→macos-13、aarch64→macos-latest
- **CI 状态**: run #45751719071 — windows/linux/macos-aarch64 成功；macos-x86_64 因 GitHub runner 容量排队（基础设施，非代码）
- **本地运行结果**: fetch_run 退出码 0；云端 Windows 产物正确识别 openstego_send 的 OpenStego 载荷，与本地一致；日志 .local-logs/run_20261126_122553.log 无 PANIC/ERROR
- **根因诊断**:
  1. WSL PATH 无 gh/cargo → 分别探测 Windows .exe
  2. gh.exe 不识别 WSL /tmp 路径 → wslpath -w 转 UNC
  3. WSL /tmp noexec 且 timeout 信号对 exe 无效 → PowerShell Start-Process 包装
  4. macos-14 标签 arm64 作业启动即取消 → 换 macos-latest
- **下一步行动**: 进入 P0 首项 strings+EXIF（用户选定），每模块带单测与黄金样本 E2E

### Iteration #4 - P0 strings + EXIF/元数据（2026-11-26）
- **Commit**: d1266a3
- **改动要点**:
  - 新增 src/strings.rs：全文件 ASCII/UTF-16LE 字符串扫描，带偏移、最小长度、UTF16 对齐
  - 新增 src/metadata.rs：JPEG 标记段扫描（JFIF/EXIF/XMP/Photoshop IRB/COM），PNG 文本块复用；collect_from_raw 支持解码失败回退
  - imageio 增加 JPEG 魔数识别与 load_jpeg（image crate jpeg feature），ImgFormat 用 Jpeg 替换死变体 Unknown
  - CLI 新增 --strings-scan/--strings-min/--meta
  - 7 个新单测（strings 4 + metadata 3），累计 11 测试
- **CI 状态**: 已推送，待云端验证
- **本地运行结果**: precheck 退出码 0；11/11 测试通过；extradata.png 准确扫出 IEND 后 foobar3；合成截断 JPEG 经回退路径正确识别 EXIF + COM(CTF{...})
- **根因诊断**:
  1. UTF16 扫描 i 从 0 起导致 data[i-1] 下溢 → 改 2 字节成对迭代
  2. 合成 JPEG 无法被 image crate 解码 → metadata 增加纯字节回退，不依赖完整解码
  3. load_auto 只认 PNG 其余按 BMP → 补 JPEG 魔数与加载器
- **下一步行动**: 云端 watch + fetch_run 验证；随后 P0 第二项 PNG 宽高 CRC 爆破

### Iteration #5 - P0 宽高爆破/文件雕刻/一键流水线（2026-11-26）
- **Commit**: fdd2abf（IHDR）、f6a3baa（carve）、f1ba8c3（analyze）
- **改动要点**:
  - src/pngcrack.rs：CRC32 查表 + IHDR 宽高爆破（先线性后二维）+ 修复写回，5 单测
  - src/carve.rs：内置 13 种 magic 签名（PNG/JPG/GIF/ZIP/RAR/7z/GZ/PDF/BMP/ELF/CLASS/SQLITE/RTF），EOF 边界识别与导出，5 单测
  - src/main.rs：--ihdr-brute/--ihdr-max/--fix-ihdr-out、--carve/--carve-out-dir、--analyze 一键五步流水线
  - 累计 21 单测全过
- **CI 状态**: 已推送，待云端验证
- **本地运行结果**:
  - precheck 退出码 0；21/21 测试
  - IHDR：篡改 prime.png 宽度后准确还原 256x256，修复字节与原件 SequenceEqual=True
  - carve：polyglot(PNG+ZIP) 准确识别 offset=244 的 ZIP 并导出，头 50 4b 03 04 正确
  - analyze：五步全跑通，同一 polyglot 同时报出 foobar3 明文、ZIP 雕刻、IEND extradata
- **根因诊断**:
  1. PowerShell 反引号转义不产生真控制字节 → 用显式 byte[] 构造 polyglot
  2. 合成 JPEG 无法解码 → metadata 纯字节回退（Iteration#4 已解决，analyze 复用）
- **下一步行动**: 云端 watch + fetch_run 验证三平台产物；P0 收尾后进入 P1（JPEG DCT 域 steghide/F5/stegpy）

### Iteration #6 - 全项目中文化（2026-11-26）
- **Commit**: bc42ae9
- **改动要点**:
  - README.md 重写为全中文完整文档（项目介绍/功能一览/安装/快速开始/参数说明/格式支持/工作原理/FAQ/从源码开发），删除冗余 README_CN.md
  - CLI 帮助全中文化：clap 自定义 help_template（用法/参数/选项），自定义中文 -h/--help 与 -V/--version，所有参数 doc 注释译为中文
  - 源码注释与用户可见报错中文化：opts/checker/extractor/imageio/result/crack/pngcrack/metadata/strings/carve，含 with_context/bail/anyhow 错误信息
  - 工作流 ci/release/build-loop 及模板的步骤名、loop_driver.sh 全部输出中文化
  - 保留项（加注释说明）：file 命令忽略列表、算法/格式技术标识符（LSB/CRC/AES 等）、测试数据字面量、history 史实
- **CI 状态**: 已推送
- **本地运行结果**: precheck 退出码 0；21/21 测试通过；--help/--version 输出全中文；构建产物正常
- **根因诊断**: clap 内置 Usage/Arguments/Options 与 Print help 为英文 → 自定义 help_template + disable 内置标志后用 ArgAction::Help/Version 重建中文项
- **下一步行动**: 按需进入 P1（JPEG DCT 域算法）

### Iteration #7 - 远程仓库规范化与 v0.1.0 正式发布（2026-11-26）
- **Commit**: 1005570（release.yml 修复）→ 0fdca41（macos-14 交叉）→ 713560f（macos-15-arm64）→ 7cb0ec0（统一 macos-latest，发布点）
- **改动要点**:
  - 重写 release.yml：tag(v*) 触发、4 平台矩阵、softprops/action-gh-release@v2 全自动发布、逐产物 SHA256、步骤中文化
  - 基于 agent/pass-crack 新建 main 并设为远程默认分支；删除全部 14 个遗留 dependabot 噪音分支；远程仅留 main + agent/pass-crack
  - 在发布提交上打中文附注标签 v0.1.0（本地旧 v0.0.x 标签不推送）
  - release/build-loop/templates 三处 macOS 矩阵统一：x86_64 与 aarch64 均跑在 macos-latest(ARM)，Intel 产物以 x86_64-apple-darwin target 交叉编译
- **CI 状态**: 最终 run 45812860024 全 success（4 构建 + 创建发布）。前序失败：run 45785009733（macos-13 排队 18min 取消）、45810340867（macos-14 零步骤取消）、45810819891（macos-15-arm64 无容量排队取消）
- **本地运行结果**: precheck 退出码 0、21/21 测试；下载发布的 Windows 产物实测 `--version`=0.1.0、中文帮助正常；SHA256 与发布页校验和逐字一致（859921f5…ba846d）
- **根因诊断（runner 标签演进，关键教训）**:
  1. macos-13 Intel runner 容量枯竭长期排队（镜像临近退役）
  2. **macos-14 镜像已于 2026-11-02 完全停止支持** → 标签被直接取消、零步骤、runner 名为空
  3. macos-15-arm64 标签虽被识别但本账户无 runner 容量，持续 queued
  4. 正解：同架构下改用容量充足且已验证可秒调度的 macos-latest，靠 Rust target 区分双架构；Apple clang/ld 原生支持 x86_64 交叉，无需额外链接器
  5. `file` 验证交叉产物确为 Mach-O x86_64（CPU type 0x01000007），与 arm64 产物架构正确区分
- **完整性校验**: 本地 HEAD = 远程 main = v0.1.0 标签提交 = 7cb0ec0；发布页 HTTP 200；附件直链 200 application/octet-stream；8 个附件（4 二进制 + 4 sha256）齐全
- **下一步行动**: 发布目标达成，结束闭环。后续按需 P1（JPEG DCT 域 steghide/F5/stegpy）

### Iteration #8 - 内置 file 类型识别，移除外部命令依赖（2026-11-27）
- **Commit**: 1649664
- **改动要点**:
  - 新增 `src/filetype.rs`：纯 Rust 内置识别器，31 条魔数规则（图像/文档/压缩包/可执行/数据库，含 RIFF 按 FourCC 二次区分 WebP/WAV/AVI）+ UTF-16 LE/BE 与 ASCII/UTF-8 文本判定（shebang/XML/BOM）；`detect(&[u8]) -> Option<String>`，识别不了返回 None（等价旧 IGNORES 过滤）
  - 删除 `src/file_cmd.rs`（std::process::Command 外部调用），补齐 Windows 原生无 file 命令的能力缺口；零新增依赖、三平台行为一致
  - checker 的 CheckState 用 `file_enabled: bool` 替代 `Option<FileCmd>`，改调 `filetype::detect`；main.rs `mod filetype`、更新 `--file` 帮助文案；result.rs 高亮逻辑不变
  - 描述统一英文小写关键词（png/jpeg/bitmap/pdf/zip/rar/7-zip），兼容 result.rs 的 `to_lowercase + starts_with` 高亮
  - 新增 8 个单测，累计 29 个测试
- **CI 状态**: run 45911982789（build-loop）四平台全 success（windows-msvc / linux-musl / macos-x86_64 交叉 / macos-aarch64），watch 退出码 0
- **本地运行结果**: precheck 退出码 0、29/29 测试；fetch_run 拉 Windows 产物实测：合成 PNG+ZIP 二进制 extradata 输出 `file: zip archive data`，`--file=false` 时不输出，开关语义正确，无 PANIC/ERROR
- **根因诊断（clippy 新版 lint）**:
  1. `x % 2 != 0` 触发 manual_is_multiple_of → 改 `!x.is_multiple_of(2)`
  2. 常量块大小 `chunks_exact(2)` 触发 chunks_exact_to_as_chunks → 改 `as_chunks::<2>().0`
  3. 描述首字母大写导致 result.rs 小写 `starts_with` 高亮失效、测试失败 → 关键词描述统一小写
- **下一步行动**: 目标达成，结束闭环。可选后续：Node.js 20 弃用警告（checkout/upload-artifact 升级）、P1 JPEG DCT 域算法

### Iteration #9 - P1 首个 DCT 域功能：JPEG JSteg/LSB 检测（2026-11-27）
- **Commit**: ee4a70b
- **改动要点**:
  - 新增纯 Rust 依赖 `libjpeg-turbo-rs` 0.9（无 C/FFI、no_std 兼容，默认 simd+std）；image/zune-jpeg 只输出像素不暴露 DCT，改用该库 `read_coefficients` 直接拿量化 DCT 系数（跳过 IDCT/色彩转换）
  - 新增 `src/jsteg.rs`：JSteg 标准规则——跳过每块 DC(block[0]) 与值为 0/1/-1 的 AC，对其余 AC 取 `unsigned_abs() & 1`，按 分量→块→zigzag 顺序收集后 MSB-first 打包；支持 BE/LE 4 字节长度前缀解析与可打印明文预览；9 个纯函数单测
  - `result.rs` 新增 `DetectResult::Jsteg{usable_coeffs,byte_len,preview}` 与 `jsteg:` 展示分支
  - `main.rs` 新增 `--jsteg`/`--jsteg-out` 标志与 `run_jsteg`（FF D8 FF 魔数校验）；`--analyze` 增加 `[6/6] JPEG JSteg` 步骤替换原 P1 占位
  - 新增黄金样本 `samples/jsteg_base.jpg`、`jsteg_embedded.jpg`（用同库 write_coefficients 做系数级注入，与提取端严格对称）
- **CI 状态**: run 45967550381 四平台全 success；**Linux musl 静态链接通过**（新依赖最大风险点排除），watch 退出码 0
- **本地运行结果**: precheck 退出码 0、38/38 测试（新增 9 个 jsteg）；本地与云端 Windows 产物均正确还原，提取字节前 37 字节与注入明文 `JSTEG_SECRET_FLAG_2026_CTF_PAYLOAD_OK` 逐字节一致，`--analyze` 的 [6/6] 分支正常触发，无 PANIC/ERROR
- **根因诊断（clippy 新版 lint）**:
  1. `0 | 1 | -1` OR 模式触发 manual_range_patterns → 改 `-1..=1`
  2. 常量块 `chunks_exact(8)` 触发 chunks_exact_to_as_chunks → 改 `as_chunks::<8>()`
  3. 关键工程决策：Python 侧无 jpegio（仅 PIL/numpy 像素级），无法做 DCT 系数注入；改用同 Rust 库的 write_coefficients 建临时注入工具生成样本，保证注入/提取同源对称，验证后删除工具
- **下一步行动**: P1 首项达成，仍在 agent/pass-crack 未合并 main。可选后续：steghide/F5 检测、Node.js 20 action 升级、README 补充 JSteg 用法

### Iteration #10 - P1 steghide/F5 JPEG DCT 盲检测（校准攻击）（2026-11-28）
- **Commit**: c1e62f4
- **改动要点**:
  - 新增 `src/jpegsteg.rs`：纯 Rust 校准攻击（decompress→裁左上 4px→同质量 compress→read_coefficients），对亮度 AC 提取四类指标——零占比、一阶直方图归一化 L1 散度、块内相邻系数共现矩阵二阶 L1 散度（针对保持一阶统计的 steghide）、块效应偏离；四维加权评分 0-100，启发式区分 F5（零收缩主导）/steghide（二阶共现主导）；12 个纯函数单测
  - `result.rs` 新增 `DetectResult::JpegDctStego` 与 `jpeg-dct:` 展示，固定附"启发式盲检测，非确定性结论，仅供研判"免责声明
  - `main.rs` 新增 `--jpeg-stego`/`--stego-out`（可写完整文本报告）与 run_jpeg_stego；`--analyze` 的 JPEG 分支同时跑 JSteg 提取与 F5/steghide 盲检测
  - 真实黄金样本：steghide_embedded/steghide_full（本机 steghide 0.6，回环验证）、f5_embedded（matthewgao/F5 Java 参考实现，用 Windows JDK21 + `--add-exports java.base/sun.security.provider=ALL-UNNAMED` 跑通，回环验证）
- **CI 状态**: run 46039047855 四平台全 success（含 musl 校准重压缩 API 跨平台可用），watch 退出码 0；precheck 50/50 测试通过
- **本地/云端运行结果（对照矩阵）**:
  - F5 样本：93/100 高度可疑、准确归因 F5（零占比 0.540 vs 校准 0.236，收缩效应显著；文件比 cover 小 12696 字节）
  - cover/jsteg/steghide：均 17-18 分低误报，校准成功
- **根因诊断（steghide 检测局限，重要诚实结论）**:
  1. steghide 用图论交换保持一阶直方图，chi-square 与一阶散度天然失效；满容量嵌入二阶共现散度仍仅 0.042，与 cover 的 0.043 无差异
  2. 根因：steghide 嵌入后文件大小几乎不变（delta≈0/-17B），图论交换只动极少量系数且不增零；校准重压缩进一步把微弱扰动压进统计噪声
  3. 无训练分类器（SRM/富模型 + SVM/CNN）时，纯启发式统计对低嵌入率 steghide 不敏感是学术界公认难点，非实现缺陷；评分通路本身经单测验证对强二阶扰动正确响应（score_cooccurrence_dominant 测试）
  4. clippy：needless_borrow（去掉 calib_blocks 前多余 &）
- **能力红线**: 本功能输出可疑度而非确定结论，不提取明文、不保证算法归因；已在代码注释、CLI 输出、--stego-out 报告中声明
- **下一步行动**: 盲检测达成且边界清晰，仍在 agent/pass-crack 未合并 main。可选：训练型富模型分类器（超出纯 Rust 无依赖范围）、Node.js 20 action 升级、README 补 DCT 章节

### Iteration #11 - 校准攻击修正：同量化表重压缩 + 显著性门控评分（2026-11-28）
- **Commit**: 3273133
- **改动要点**:
  - 校准器重写：`calibrate` 改用 `encode::pipeline::compress_custom_quant`，复用原图 `JpegCoefficients.quant_tables` 的 slot0(luma)/slot1(chroma) 量化表（自然序，与编码器入参约定一致，无需 zigzag 转换），落实 Fridrich 校准"量化矩阵不变、仅 8×8 网格错位"的核心要求；替换原来固定 quality=92 的错误做法
  - 评分模型重写：`score_report` 引入"显著性门控"——五维（零收缩30/共现25/一阶15/变化15/块效应15）各自越阈才计分，亚阈值校准噪声一律记 0，越阈后按超阈强度给 0.5~1.0 倍权重；阈值依据同表校准后真实样本重标（zero 0.02/hist 0.10/cooc 0.06/var 0.30/block 0.15）
  - 归因：zero_lift≥0.02 判 F5（同表校准后非 F5 最大 zero_lift 仅 0.0011，F5 为 0.048，约 44 倍间隔）；零占比正常而共现/变化越阈判 steghide
  - 新增低纹理非标准量化表黄金样本 steghide_smooth_base.jpg / steghide_smooth.jpg 与门控回归单测 `score_subthreshold_noise_does_not_accumulate`，累计 55 测试
- **CI 状态**: run #46047990366 四平台全 success（windows-msvc / linux-musl / macos-x86_64 / macos-aarch64），watch 退出码 0；仅有 Node.js 20 弃用 annotation（基础设施，非失败）
- **本地运行结果**: precheck 退出码 0、55/55 测试、fmt/clippy -D warnings 全过
- **云端产物端到端（fetch_run 运行 #46047990366 Windows exe，均退出码 0 无 PANIC/ERROR）**:
  - f5_embedded.jpg：99/100 高度可疑、归因 F5（零占比 0.540 vs 同表校准 0.492，一阶 0.115、共现 0.164）
  - steghide_smooth_base.jpg（旧逻辑误报 67/100）：**0/100 Clean**，回归修复确认
  - 其余 5 个非 F5 样本（jsteg cover/embedded、steghide 低/满容量、低纹理 steghide）全部 0/100 Clean
- **根因诊断（关键认知）**:
  1. 旧固定 Q92 校准在**非标准量化表**图上引入二次量化噪声：低纹理平滑图 luma 量化表 DC=5（远细于 Q92 标准表），用错表重压缩使校准零占比 0.954 偏离真实 0.968，单是零占比就虚高 +0.014，五维亚阈值偏差累加炸出 67 分假阳性
  2. 同表重压缩后该图校准零占比回到 0.968006（与待测 0.968145 几乎相同），histDiv 0.0615→0.0156、coocDiv 0.0476→0.0215，假阳性信号消失
  3. 旧"线性加权累加"模型的结构性缺陷：任何不显著的微小偏离都按比例给分，多维噪声叠加即误报；门控模型从机制上杜绝此类假阳性
  4. F5 在同表校准下 zero_lift 虽从 0.304 收敛到 0.048（收缩效应部分被同表重压缩吸收），但仍 44 倍于非 F5 上限，配合一阶/共现越阈，综合 99 分，检测力不降反升
- **诚实边界（保持不变）**: 高纹理图上的低嵌入率/满容量 steghide 与干净图各维特征无差异（同表校准后 cooc 0.021-0.023 vs cover 0.024），无训练富模型分类器时单图启发式无法区分，属学界公认难点；低纹理高嵌入率 steghide_smooth 与同源干净图在同表校准后同样不可分（均 0 分），不再靠二次量化噪声制造无统计学依据的"区分"
- **环境备忘**: 本机 WSL 无 git 凭据助手且无 System32 PATH，直接 `git push` 会在不可见的账号密码提示上挂起；解法为 `GIT_TERMINAL_PROMPT=0` + 一次性 `https://x-access-token:<gh token>@...` URL 推送（token 不落仓库配置），fetch_run 前需 `export PATH` 补 /mnt/c/Windows/System32 与 WindowsPowerShell/v1.0
- **下一步行动**: 盲检测假阳性根因修复且云端验证达成，仍在 agent/pass-crack 未合并 main。可选：Node.js 20 action 升级、README 补 DCT/盲检测章节

### Iteration #12 - PNG/BMP LSB 卡方（chi-square）统计攻击（2026-11-28）
- **Commit**: 9af1d20
- **改动要点**:
  - 新建 `src/chisq.rs`：纯 std 手写 Lanczos-7 `ln_gamma`、正则化下不完全伽马 `gammp`（x<a+1 级数展开，否则 Lentz 连分式，迭代 200、容差 3e-12），零新增依赖实现卡方上侧 p 值 `chi_pvalue=1-P(df/2,chi2/2)`
  - 统计层：256 桶 `channel_histogram`、128 个 POC 配对的 `chi_square`（expected>0 过滤、df=k-1）、沿扫描线增量分块的 `analyze_channel`（p 值曲线 + 嵌入比例估计）、`analyze_image` 四通道汇总
  - 双指标判定：除全图 p 外引入曲线峰值 `p_peak`，取 max(p_full,p_peak) 下结论，解决"前段嵌入后段原始"导致全图 p 被稀释的漏报；alpha 恒定（有效配对<2）自动标记 usable=false 跳过
  - `result.rs` 新增 `DetectResult::ChiSquareLsb` 与分级着色 Display（≥95 红/≥50 黄/其余灰）+ 固定免责声明
  - `main.rs` 新增 `--chi-square/--chi-channel(默认rgb,可all)/--chi-blocks(默认20)` 与 `run_chi_square`，挂入早返回链；`run_analyze` 第 6 步位图触发卡方，并把历史混用的 `[n/5]` 与 `[6/6]` 统一为运行期 `[n/6]`（位图/JPEG 第 6 步互斥）
  - README 补独立章节、功能表、参数表、格式支持、工作原理、能力边界
  - 新增 11 个单测（伽马临界值 df=1/2/10→p≈0.05、极值、合成均衡/偏斜直方图、退化 alpha、四通道汇总），累计 **66 测试全过**
- **CI 状态**: run #46055349826 四平台全 success（windows-msvc/linux-musl/macos-x86_64/macos-aarch64），watch 退出码 0；仅 Node.js 20 弃用 annotation
- **本地/云端运行结果**:
  - OpenStego（1b,rgb,lsb 真实部分嵌入）：全图 p 被稀释到 0.06–0.32，但分块曲线前段 p=1.00，峰值判据正确输出三通道"疑似 LSB 嵌入 100/100"；fetch_run 云端 Windows 产物逐字节复现，退出码 0 无 PANIC
  - 真实干净图 Steganography_original：三通道 p=0.0000，无误报
  - flower_rgb3（实测载荷在 **bit3 非 LSB**）：bit0 卡方 p=0，正确印证"仅对 LSB 位平面敏感"的能力边界
  - JPEG 输入被正确 bail 拒绝（提示改用 --jpeg-stego）；--chi-channel all 时恒定 alpha 正确跳过
- **根因/认知**:
  1. 合成随机像素图的 LSB 天然近 50/50 均衡，无法模拟真实照片 LSB 偏态，做负样本会误报——卡方攻击本质依赖真实图像统计先验，负样本须用真实照片，已删除无效合成图
  2. 真实样本里 OpenStego 是部分嵌入，全图 p 钝化，必须靠分块曲线峰值才能检出，这是相对教科书"只算全图 chi2"的关键工程修正
  3. clippy 1.100：needless_range_loop（改数组 fill）、chunks_exact_to_as_chunks（测试改 as_chunks_mut）、bool_comparison（改 !）、unused_mut
- **能力红线**: 仅对顺序 LSB 位平面替换敏感；对随机/非顺序散布、非 LSB 位、调色板索引 BMP、极低比例嵌入、F5/steghide 等 DCT 算法无效；输出统计概率非确定结论，已在代码注释、CLI、README 声明
- **下一步行动**: 卡方攻击达成且云端验证，仍在 agent/pass-crack 未合并 main。可选：Camouflage 直接还原（需先补全逆向/20MB key）、wbStego 提取、Node.js 20 action 升级

### Iteration #13 - 固化收口：PR #16 合并 + v0.2.0 发布与哈希核验（2026-11-28）
- **改动要点**:
  - PR #16（Iteration #8–#12 全部 12 提交）合并 main：完整 ci.yml 门禁（3 平台 fmt/clippy/test）**首次覆盖** agent/pass-crack 分支（此前仅 build-loop 构建），全绿后 merge commit `906b1f5`
  - `.trae/` IDE 目录入 .gitignore（`728f413`）；PR #15（anyhow 1.0.100→1.0.105，lock-only 常规补丁，6 检查全绿）squash 合并（`2043a7c`）
  - Cargo.toml/Cargo.lock bump 0.2.0（`0cf6871`）+ 注释 tag `v0.2.0` 触发 release.yml
- **CI 状态**: 发布 run 46148473699 completed/success，四平台二进制 + .sha256 sidecar 全部产出；耗时 >15 分钟（v0.1.0 仅 ~2 分钟），macos-x86_64/windows/linux 三路 runner 排队所致，macos-aarch64 先行完成
- **发布产物核验（fetch 下载实测）**:
  - Windows exe SHA-256 `32dfc747fb3c67ef6585d0c8221d86cd4a0ff062a4d50e1dce82c5cb4fbe33b4` 与官方 sidecar 一致；留档 `02-Misc/stegecracker/_verify_v020/`
  - 黄金样本回环全过：卡方 openstego_send 三通道 100/100、JSteg 明文 `JSTEG_SECRET_FLAG_2026_CTF_PAYLOAD_OK` 逐字提取、F5 盲检测 99/100 归因 F5、干净图 steghide_smooth_base 0/100，退出码全 0
- **GATE 登记**: `00-Docs/reports/备赛工具清单与安全审查报告_v0.1.md` 3.1 加更新块 + 3.2 第 10 行同步——供应链层已可核验（自有 Release + sidecar），**GATE 维持 RECHECK**，缺隔离 VM 零外联首跑，五线未全过前禁带赛场
- **环境备忘**:
  1. 本机 Windows git push 无凭据助手会挂起，用一次性 token URL `https://x-access-token:$(gh auth token)@github.com/...` 推送（与 #11 WSL 结论同源）
  2. `gh release download --pattern` 需匹配完整资产名（`*windows*` 而非 `windows*`）
  3. tag 在 PR #15 合并前打出，故 v0.2.0 二进制内 anyhow 仍为 1.0.100（lock-only 补丁，无 CVE，无需重切 tag）
- **下一步行动**: **P1 steghide 口令爆破（stegseek 对标）立项**——纯 Rust 复刻 steghide 提取通路（口令 SHA-1 派生 → Blowfish-CBC 头部解密校验 → mhash 型 PRNG 采样位置选择 → DCT 系数回读），难点在采样选择与嵌入算法的逐位一致性，验证以 `samples/steghide_embedded.jpg` 回环 + 与 stegseek 交叉比对，预估 2–3 个迭代。其余候选：wbStego 提取、Node.js 20→24 actions 升级
