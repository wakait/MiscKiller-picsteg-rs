//! OpenStego 口令字典爆破。
//!
//! 加密机制（源自 OpenStegoCrypto.java）：
//! - PBEWithHmacSHA256AndAES_128/256
//! - 硬编码 8 字节 SALT，PBKDF2-HMAC-SHA256 仅迭代 7 次
//! - 密文前置 JCE AlgorithmParameters（ASN.1 SEQUENCE，内含 16 字节 IV）
//! - AES-CBC + PKCS5/PKCS7 padding
//!
//! 命中判据：参数 ASN.1 标记合法 + PKCS7 padding 合法 +（可选）zlib 解压成功。

use crate::extractor;
use crate::imageio::Image;
use crate::opts::Options;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// 与 OpenStegoCrypto.java 完全一致的硬编码 salt
const SALT: [u8; 8] = [0x28, 0x5F, 0x71, 0xC9, 0x1E, 0x35, 0x0A, 0x62];
/// PBE 迭代次数（OpenStego 固定为 7，极低，适合字典爆破）
const ITER_COUNT: u32 = 7;
const MAGIC: &[u8] = b"OPENSTEGO";

/// 从提取数据中解析出的 OpenStego 加密载荷
pub struct OpenStegoPayload {
    pub version: u8,
    pub data_len: u32,
    pub compress: bool,
    pub encrypt_algo: u8,
    pub fname: String,
    /// 加密体：[param_len][algorithm params][AES-CBC 密文]
    pub enc_blob: Vec<u8>,
}

/// 爆破成功结果
pub struct CrackHit {
    pub password: String,
    pub key_bits: usize,
    pub plaintext: Vec<u8>,
}

/// 从 LSB 提取字节流中定位并解析 OPENSTEGO 载荷
pub fn parse_openstego(data: &[u8]) -> Option<OpenStegoPayload> {
    let pos = data.windows(MAGIC.len()).position(|w| w == MAGIC)?;
    let h = pos + MAGIC.len();
    if data.len() < h + 9 {
        return None;
    }
    let version = data[h];
    let data_len = u32::from_le_bytes([data[h + 1], data[h + 2], data[h + 3], data[h + 4]]);
    let channel_bits = data[h + 5];
    let _ = channel_bits;
    let fname_len = data[h + 6] as usize;
    let compress = data[h + 7] != 0;
    let encrypt_algo = data[h + 8];
    let fname_start = h + 9;
    if data.len() < fname_start + fname_len {
        return None;
    }
    let fname = String::from_utf8_lossy(&data[fname_start..fname_start + fname_len]).to_string();
    let enc_start = fname_start + fname_len;
    if enc_start >= data.len() {
        return None;
    }
    Some(OpenStegoPayload {
        version,
        data_len,
        compress,
        encrypt_algo,
        fname,
        enc_blob: data[enc_start..].to_vec(),
    })
}

/// 从 JCE AlgorithmParameters ASN.1 结构中提取 16 字节 IV。
/// OpenStego 使用标准 PBES2 风格参数，IV 以 OCTET STRING 形式内嵌。
fn extract_iv(params: &[u8]) -> Option<[u8; 16]> {
    // 找到 16 字节 OCTET STRING：标记 0x04 + 长度 0x10 + 16 字节
    let mut i = 0;
    while i + 18 <= params.len() {
        if params[i] == 0x04 && params[i + 1] == 0x10 {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&params[i + 2..i + 18]);
            return Some(iv);
        }
        i += 1;
    }
    None
}

/// 用指定密钥长度尝试解密，成功返回明文（cbc 已自动校验并去除 PKCS7 填充）
fn try_decrypt(enc_blob: &[u8], password: &str, key_len: usize) -> Option<Vec<u8>> {
    if enc_blob.is_empty() {
        return None;
    }
    let param_len = enc_blob[0] as usize;
    if param_len == 0 || 1 + param_len >= enc_blob.len() {
        return None;
    }
    let params = &enc_blob[1..1 + param_len];
    let ciphertext = &enc_blob[1 + param_len..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return None;
    }
    // 粗略校验参数确为 ASN.1 SEQUENCE
    if params.first() != Some(&0x30) {
        return None;
    }
    let iv = extract_iv(params)?;

    let mut key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &SALT, ITER_COUNT, &mut key);

    let mut buf = ciphertext.to_vec();
    let plain = match key_len {
        16 => Aes128CbcDec::new_from_slices(&key, &iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?,
        32 => Aes256CbcDec::new_from_slices(&key, &iv)
            .ok()?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .ok()?,
        _ => return None,
    };
    // decrypt_padded_mut::<Pkcs7> 成功即代表填充合法且已被去除
    Some(plain.to_vec())
}

/// 对单个密码依次尝试 AES-128 / AES-256
fn try_password(enc_blob: &[u8], password: &str) -> Option<(usize, Vec<u8>)> {
    if let Some(pt) = try_decrypt(enc_blob, password, 16) {
        return Some((128, pt));
    }
    if let Some(pt) = try_decrypt(enc_blob, password, 32) {
        return Some((256, pt));
    }
    None
}

/// 若载荷声明压缩，尝试 zlib 解压作为强命中判据
fn confirm_plaintext(plain: &[u8], compress: bool) -> bool {
    if !compress {
        // 无压缩时 PKCS7 合法即视为命中（padding 已提供强约束）
        return true;
    }
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut dec = ZlibDecoder::new(plain);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map(|_| !out.is_empty())
        .unwrap_or(false)
}

/// 执行字典爆破。`opts` 用于控制 LSB 提取方式（默认 b1,rgb,lsb,xy）。
pub fn crack_openstego(
    image: &Image,
    wordlist: &Path,
    opts: &Options,
) -> anyhow::Result<Option<CrackHit>> {
    // 1. 提取 LSB 载荷
    let mut title = String::new();
    let extracted = extractor::extract(image, opts, &mut title);

    // 2. 解析 OPENSTEGO 结构
    let payload = parse_openstego(&extracted)
        .ok_or_else(|| anyhow::anyhow!("未在提取数据中找到 OPENSTEGO 载荷（提取方式: {title}）"))?;

    println!(
        "[i] OpenStego v{} fname={:?} compress={} encrypt_algo={} data_len={}",
        payload.version, payload.fname, payload.compress, payload.encrypt_algo, payload.data_len
    );

    // 3. 逐行读取字典
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
        if let Some((bits, plain)) = try_password(&payload.enc_blob, password)
            && confirm_plaintext(&plain, payload.compress)
        {
            println!("[+] 命中！共尝试 {tried} 个密码");
            return Ok(Some(CrackHit {
                password: password.to_string(),
                key_bits: bits,
                plaintext: plain,
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
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    /// 构造与 OpenStegoCrypto 布局一致的加密体：[param_len][params(含IV)][密文]
    fn make_openstego_blob(password: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 16];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &SALT, ITER_COUNT, &mut key);
        let iv = [0x42u8; 16];

        // 仿 JCE 参数：SEQUENCE 内嵌入 16 字节 OCTET STRING（extract_iv 仅需 04 10 + IV）
        let mut params = vec![0x30, 0x14];
        params.push(0x04);
        params.push(0x10);
        params.extend_from_slice(&iv);

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes128CbcEnc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        buf.truncate(ct_len);

        let mut blob = vec![params.len() as u8];
        blob.extend_from_slice(&params);
        blob.extend_from_slice(&buf);
        blob
    }

    #[test]
    fn correct_password_is_recovered() {
        let secret = b"hello openstego dictionary attack";
        let blob = make_openstego_blob("s3cr3t", secret);
        // 正确密码应解密成功
        let (bits, pt) = try_password(&blob, "s3cr3t").expect("正确密码必须命中");
        assert_eq!(bits, 128);
        assert_eq!(pt, secret);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let secret = b"hello openstego dictionary attack";
        let blob = make_openstego_blob("s3cr3t", secret);
        // 错误密码：padding 校验应拒绝（极小概率偶然合法，故多试几个）
        for wrong in ["wrong", "password", "123456", "admin", "openstego"] {
            assert!(
                try_password(&blob, wrong).is_none(),
                "错误密码 {wrong} 不应命中"
            );
        }
    }

    #[test]
    fn iv_extraction_finds_octet_string() {
        let mut params = vec![0x30, 0x14, 0x04, 0x10];
        params.extend_from_slice(&[0xABu8; 16]);
        let iv = extract_iv(&params).expect("应提取到 IV");
        assert_eq!(iv, [0xABu8; 16]);
    }

    #[test]
    fn parse_openstego_header() {
        // OPENSTEGO + 9 字节头 + 文件名 + 加密体
        let mut data = b"OPENSTEGO".to_vec();
        data.push(1); // version
        data.extend_from_slice(&100u32.to_le_bytes()); // data_len
        data.push(1); // channel_bits
        let fname = b"secret.jpg";
        data.push(fname.len() as u8); // fname_len
        data.push(1); // compress
        data.push(1); // encrypt
        data.extend_from_slice(fname);
        data.push(0x14); // 加密体 param_len（后续内容不影响头部解析）

        let p = parse_openstego(&data).expect("应解析成功");
        assert_eq!(p.version, 1);
        assert_eq!(p.fname, "secret.jpg");
        assert!(p.compress);
        assert_eq!(p.enc_blob[0], 0x14);
    }
}
