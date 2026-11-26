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
