//! steghide JPEG 口令字典爆破（对标 stegseek 的 magic 快速校验）。
//!
//! stegseek 的核心加速思路：**不做 AES 解密、不做完整提取**，仅用口令派生的 PRNG
//! 复现 steghide 的采样路径，校验嵌在量化 DCT 系数里的 24-bit magic。每个候选口令
//! 只需 1 次 MD5 + 至多 72 次 LCG/查表，开销极低，适合大字典。
//!
//! 算法常量与流程均以 stegseek 0.6 源码为权威依据（Cracker.cc / JpegFile.cc /
//! JpegSampleValue.h / PseudoRandomSource.h / EmbData.h）：
//! - 口令经 MD5 得 16 字节摘要，按 4 个小端 u32 异或折叠为 PRNG seed；
//! - PRNG 为 32 位 LCG（模 2^32，依赖 u32 溢出）：A=1367208549，C=1；
//! - 采样数组只含**非零** DCT 系数（含直流 DC，仅跳过值为 0 的系数），嵌入值取
//!   `|系数| % 2`；
//! - 每 3 个采样（SamplesPerVertex）聚成 1 个嵌入 bit，共校验 magic 的 24 bit。
//!
//! 与 [`crate::jsteg`] 的关键差异：JSteg 跳过 DC 且跳过 0/1/-1；steghide **不跳过
//! DC、不跳过 ±1，只跳过 0**，故本模块独立构建嵌入值数组。
//!
//! 能力边界（Phase 1）：仅支持 JPEG、仅还原口令、不产出明文；magic 为 24-bit 概率
//! 校验，存在理论假阳性（约 2^-24），可用 `steghide info -p` 复核。完整明文提取
//! （Selector 图论匹配 + AES-CBC + zlib）属后续 Phase 2。

use libjpeg_turbo_rs::read_coefficients;
use md5::compute as md5_compute;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// steghide EmbData::Magic，24 bit（值 0x73688D，按 bit0=LSB 在前逐位比对）。
const MAGIC: u32 = 0x73688D;
/// magic 的比特数（EmbData::NBitsMagic）。
const N_BITS_MAGIC: usize = 24;
/// 每个顶点采样数（JpegFile::SamplesPerVertex）。
const SAMPLES_PER_VERTEX: usize = 3;
/// 嵌入值模数（JpegFile::EmbValueModulus），JPEG 下为 2。
const EMB_VALUE_MODULUS: u32 = 2;
/// 每个 8x8 块的系数数（JpegFile::CoeffPerBlock）。
const COEFF_PER_BLOCK: usize = 64;
/// LCG 乘子（PseudoRandomSource::A）。
const LCG_A: u32 = 1_367_208_549;
/// LCG 增量（PseudoRandomSource::C）。
const LCG_C: u32 = 1;
/// 2^32，浮点归一化常数，与 stegseek 字面量一致。
const TWO_POW_32: f64 = 4_294_967_296.0;
/// JPEG 魔数 FF D8 FF。
const JPEG_SIG: [u8; 3] = [0xFF, 0xD8, 0xFF];

/// 爆破成功结果（Phase 1 仅含口令，不含明文）。
#[derive(Debug, Clone)]
pub struct SteghideHit {
    /// 命中的口令
    pub password: String,
    /// 命中前累计尝试的候选口令数
    pub tried: u64,
}

/// 把 16 字节 MD5 摘要按 4 个**小端** u32 异或折叠为 PRNG seed。
///
/// 对应 stegseek `Cracker::verifyMagic(string)` 中 mhash 输出 `UWORD32 hash[4]`
/// 后逐元素异或（x86 小端）。
fn fold_digest(digest: &[u8; 16]) -> u32 {
    let (chunks, _remainder) = digest.as_chunks::<4>();
    let mut seed = 0u32;
    for chunk in chunks {
        seed ^= u32::from_le_bytes(*chunk);
    }
    seed
}

/// 由口令字节计算 steghide PRNG seed：MD5 → 小端 u32 异或折叠。
fn md5_seed(passphrase: &[u8]) -> u32 {
    fold_digest(&md5_compute(passphrase).0)
}

/// LCG 单次迭代：`seed = seed * A + C (mod 2^32)`，依赖 u32 wrapping 溢出。
fn next_lcg(seed: u32) -> u32 {
    seed.wrapping_mul(LCG_A).wrapping_add(LCG_C)
}

/// 单个量化 DCT 系数到 steghide 嵌入值的纯函数映射：`|coef| % 2`。
/// 调用方负责只对非零系数取值（零系数不进入采样数组）。
fn coef_to_embvalue(coef: i16) -> u8 {
    (coef.unsigned_abs() % 2) as u8
}

/// 遍历全部 DCT 系数构建 steghide 嵌入值数组。
///
/// 线性化顺序为 分量 → 块 → 块内 64 系数（含 block[0] 直流 DC），与 libjpeg-turbo-rs
/// 的 `components[].blocks` 布局对应；**仅跳过值为 0 的系数**。返回数组长度即
/// stegseek 的 `numSamples`。
fn collect_embedded_values(jpeg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let coefficients =
        read_coefficients(jpeg).map_err(|e| anyhow::anyhow!("解析 JPEG DCT 系数失败：{e}"))?;

    let mut embedded = Vec::new();
    for component in &coefficients.components {
        for block in &component.blocks {
            for &coef in &block[0..COEFF_PER_BLOCK] {
                if coef != 0 {
                    embedded.push(coef_to_embvalue(coef));
                }
            }
        }
    }
    Ok(embedded)
}

/// 用指定 seed 复现 steghide 采样路径并校验 24-bit magic（忠实移植 stegseek
/// `Cracker::verifyMagic(UWORD32 seed)`）。载体过短或任一 magic bit 不符返回 false；
/// 采样索引发生碰撞时按 stegseek 策略视为通过（罕见，交给严格提取复核）。
fn verify_magic(seed: u32, embedded: &[u8]) -> bool {
    let num_samples = embedded.len();
    let embvalues_requested = N_BITS_MAGIC;

    // 载体太短，不足以容纳 magic 所需采样（stegseek 同样 return false）
    if SAMPLES_PER_VERTEX * embvalues_requested >= num_samples {
        return false;
    }

    // rngBuf 实际只用到前 SAMPLES_PER_VERTEX * embvalues_requested（=72）项
    let mut rng_buf: Vec<u32> = Vec::with_capacity(SAMPLES_PER_VERTEX * embvalues_requested);
    let mut state = seed;
    let mut sv_idx = 0usize;

    for i in 0..embvalues_requested {
        let mut ev: u32 = 0;
        for _ in 0..SAMPLES_PER_VERTEX {
            state = next_lcg(state);
            // 浮点归一化后截断为整数（C++ 浮点赋 UWORD32 即向零取整，值恒非负）
            let val_idx = sv_idx as u32
                + ((state as f64 / TWO_POW_32) * (num_samples - sv_idx) as f64) as u32;
            let val_idx = val_idx as usize;

            // RNG 碰撞检测：与已选索引重复则视为通过（stegseek 同款策略）
            if rng_buf.iter().take(sv_idx).any(|&v| v == val_idx as u32) {
                return true;
            }
            rng_buf.push(val_idx as u32);

            ev = (ev + embedded[val_idx] as u32) % EMB_VALUE_MODULUS;
            sv_idx += 1;
        }

        // JPEG 下 bitsPerEmbValue=1，每轮只比对 1 bit；magic 按 bit0=LSB 在前，
        // 故 bitsSeen 即外层迭代下标 i（stegseek: bitsSeen = i*bitsPerEmbValue + k）。
        let current_bit = ev & 1;
        let magic_bit = (MAGIC >> i) & 1;
        if current_bit != magic_bit && i < 25 {
            return false;
        }
    }
    true
}

/// 对单个候选口令执行 magic 校验。
fn try_passphrase(passphrase: &[u8], embedded: &[u8]) -> bool {
    verify_magic(md5_seed(passphrase), embedded)
}

/// steghide 字典爆破入口：读取 JPEG、构建嵌入值数组、逐行尝试字典口令。
///
/// 首个通过 magic 校验的口令即返回（与 OpenStego 爆破行为一致）；字典耗尽未命中
/// 返回 `Ok(None)`。
pub fn crack_steghide(jpeg_path: &Path, wordlist: &Path) -> anyhow::Result<Option<SteghideHit>> {
    let raw =
        fs::read(jpeg_path).map_err(|e| anyhow::anyhow!("无法读取图片 {:?}: {e}", jpeg_path))?;
    if raw.len() < JPEG_SIG.len() || raw[0..3] != JPEG_SIG {
        anyhow::bail!("steghide magic 爆破仅支持 JPEG 输入（缺少 FF D8 FF 文件头）");
    }

    let embedded = collect_embedded_values(&raw)?;
    println!(
        "[i] 可用非零 DCT 系数（numSamples）= {}，magic 需采样 {} 个",
        embedded.len(),
        SAMPLES_PER_VERTEX * N_BITS_MAGIC
    );

    let file = fs::File::open(wordlist)
        .map_err(|e| anyhow::anyhow!("无法打开字典 {:?}: {e}", wordlist))?;
    let reader = BufReader::new(file);

    let mut tried: u64 = 0;
    for line in reader.lines() {
        let password = line?;
        let password = password.trim_end_matches('\r');
        if password.is_empty() {
            continue;
        }
        tried += 1;

        if try_passphrase(password.as_bytes(), &embedded) {
            println!("[+] 命中！共尝试 {tried} 个密码");
            return Ok(Some(SteghideHit {
                password: password.to_string(),
                tried,
            }));
        }

        if tried.is_multiple_of(5000) {
            println!("[.] 已尝试 {tried} 个密码...");
        }
    }

    println!("[-] 字典耗尽（{tried} 个密码），未命中");
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_digest_uses_little_endian_xor() {
        // 4 个小端 u32：0x04030201 / 0x08070605 / 0x0C0B0A09 / 0x100F0E0D
        let digest: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let expected = 0x0403_0201u32 ^ 0x0807_0605 ^ 0x0C0B_0A09 ^ 0x100F_0E0D;
        assert_eq!(fold_digest(&digest), expected);
    }

    #[test]
    fn md5_seed_is_deterministic() {
        // 同一口令两次结果一致，且不同口令通常不同
        let a = md5_seed(b"ctf123");
        let b = md5_seed(b"ctf123");
        let c = md5_seed(b"other-password");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn lcg_wrapping_sequence() {
        // 从 seed=0 出发的确定性序列（wrapping 算术）
        let s1 = next_lcg(0);
        assert_eq!(s1, 1);
        let s2 = next_lcg(s1);
        assert_eq!(s2, LCG_A.wrapping_add(1));
        let s3 = next_lcg(s2);
        assert_eq!(s3, s2.wrapping_mul(LCG_A).wrapping_add(1));
    }

    #[test]
    fn coef_embvalue_abs_mod_two() {
        assert_eq!(coef_to_embvalue(2), 0);
        assert_eq!(coef_to_embvalue(3), 1);
        assert_eq!(coef_to_embvalue(-2), 0);
        assert_eq!(coef_to_embvalue(-3), 1);
        assert_eq!(coef_to_embvalue(100), 0);
        assert_eq!(coef_to_embvalue(-101), 1);
    }

    #[test]
    fn verify_magic_rejects_wrong_seed() {
        // 构造一段确定性嵌入数组，多个错误 seed 都应被拒绝
        let embedded: Vec<u8> = (0..4096u32).map(|i| (i % 3) as u8).collect();
        let mut rejected = 0;
        for seed in [1u32, 2, 42, 999, 123_456, 0xDEAD_BEEF] {
            if !verify_magic(seed, &embedded) {
                rejected += 1;
            }
        }
        // 24-bit 约束下，6 个任意 seed 不应全部误判通过
        assert!(rejected >= 5, "错误 seed 误判通过过多: rejected={rejected}");
    }

    /// 测试辅助：用与生产代码同款 LCG/采样逻辑，正向构造一条使 `seed` 的 magic
    /// 校验通过的嵌入数组（先清零，再在每条采样路径上写入所需 bit）。
    fn build_embedded_for_seed(seed: u32, num_samples: usize) -> Vec<u8> {
        let mut embedded = vec![0u8; num_samples];
        let mut state = seed;
        let mut sv_idx = 0usize;

        for i in 0..N_BITS_MAGIC {
            let magic_bit = ((MAGIC >> i) & 1) as u8;
            for _ in 0..SAMPLES_PER_VERTEX {
                state = next_lcg(state);
                let val_idx = sv_idx as u32
                    + ((state as f64 / TWO_POW_32) * (num_samples - sv_idx) as f64) as u32;
                // 把该采样点设为目标 bit（三点之和模 2 即目标 bit）
                embedded[val_idx as usize] = magic_bit;
                sv_idx += 1;
            }
        }
        embedded
    }

    #[test]
    fn verify_magic_accepts_constructed_path() {
        let seed = 0xCAFE_BABEu32;
        let embedded = build_embedded_for_seed(seed, 5000);
        assert!(
            verify_magic(seed, &embedded),
            "正向构造的嵌入数组应使该 seed 通过 magic 校验"
        );
        // 另一无关 seed 不应通过
        assert!(!verify_magic(seed ^ 0x0000_0001, &embedded));
    }

    #[test]
    fn verify_magic_guards_short_carrier() {
        // 采样需求 72，数组过短必须直接拒绝，不能越界
        let tiny = vec![1u8; 10];
        assert!(!verify_magic(12345, &tiny));
        let boundary = vec![0u8; SAMPLES_PER_VERTEX * N_BITS_MAGIC]; // 恰好 72，>= 仍拒绝
        assert!(!verify_magic(12345, &boundary));
    }

    #[test]
    fn constructed_indices_stay_in_bounds() {
        // 正向构造时所有 val_idx 必须落在 num_samples 内
        let num_samples = 1000usize;
        let embedded = build_embedded_for_seed(777, num_samples);
        assert_eq!(embedded.len(), num_samples);
        // 能跑通 verify_magic 且不 panic 即证明索引全程合法
        let _ = verify_magic(777, &embedded);
    }
}
