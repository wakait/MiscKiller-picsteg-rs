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
