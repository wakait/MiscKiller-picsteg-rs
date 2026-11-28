//! 位平面（bit plane）可视化导出（stegsolve 类人工研判辅助）。
//!
//! 把 RGBA8 像素中指定通道的某一个二进制位（bit0=LSB … bit7=MSB）提取出来，
//! 渲染成黑白二值灰度 PNG：该位为 1 记白（255）、为 0 记黑（0）。自然图像的
//! 高位平面连续、接近原图轮廓，低位平面呈细碎随机噪点；若 LSB 平面出现结构化
//! 文字/图案或异常规律，往往提示像素域 LSB 隐写。
//!
//! 能力红线：产出的是**辅助人工研判的可视化材料，不是确定性检测结论**；仅反映
//! 像素域位平面，对 JPEG DCT 域算法（F5/steghide/JSteg）、调色板索引隐写不适用，
//! 加密/压缩载荷可能只呈随机噪点而无可读图案。需结合 LSB 提取、卡方 p 值交叉验证。

use crate::imageio::Image;
use image::{ExtendedColorType, save_buffer};
use std::path::{Path, PathBuf};

/// 通道索引对应的文件名符号：0=R, 1=G, 2=B, 3=A。
const CH_NAMES: [&str; 4] = ["R", "G", "B", "A"];

/// 提取单通道指定位平面，返回长度 `width*height` 的 L8 灰度缓冲。
///
/// - `ch`：通道索引 0=R, 1=G, 2=B, 3=A；`bit`：位序号 0=LSB … 7=MSB。
/// - 输入 `pixels` 为每像素 4 字节紧密排列的 RGBA8。
/// - 输出每像素 1 字节，目标位为 1 → 255（白），为 0 → 0（黑）。
pub fn bit_plane(pixels: &[u8], width: u32, height: u32, ch: usize, bit: u8) -> Vec<u8> {
    debug_assert!(ch < 4, "通道索引必须在 0..4 内");
    debug_assert!(bit < 8, "位序号必须在 0..8 内");
    let n = (width as usize) * (height as usize);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let v = pixels[i * 4 + ch];
        out.push(((v >> bit) & 1) * 255);
    }
    out
}

/// 解析位平面规格：`all` → 0..8；单个 `"3"`；逗号列表 `"0,1,7"`。
/// 去重并保持升序，过滤 ≥8 的非法值；无合法项时回退为全部 8 位。
pub fn parse_bits(spec: &str) -> Vec<u8> {
    let spec = spec.trim().to_lowercase();
    if spec == "all" || spec.is_empty() {
        return (0u8..8).collect();
    }
    let mut bits: Vec<u8> = Vec::new();
    for part in spec.split(',') {
        if let Ok(n) = part.trim().parse::<u8>()
            && n < 8
            && !bits.contains(&n)
        {
            bits.push(n);
        }
    }
    if bits.is_empty() {
        (0u8..8).collect()
    } else {
        bits.sort_unstable();
        bits
    }
}

/// 按通道×位组合导出黑白位平面 PNG 到 `out_dir`，返回成功写出的文件数。
///
/// 文件命名 `{stem}_{R|G|B|A}_bit{0..7}.png`；目录不存在时自动创建。
pub fn export_planes(
    img: &Image,
    stem: &str,
    channels: &[u8],
    bits: &[u8],
    out_dir: &Path,
) -> anyhow::Result<usize> {
    std::fs::create_dir_all(out_dir)?;
    let mut count = 0usize;
    for &ch in channels {
        let ch = ch as usize;
        let Some(&name) = CH_NAMES.get(ch) else {
            continue;
        };
        for &bit in bits {
            let buf = bit_plane(&img.pixels, img.width, img.height, ch, bit);
            let file_name = format!("{stem}_{name}_bit{bit}.png");
            let path: PathBuf = out_dir.join(file_name);
            save_buffer(&path, &buf, img.width, img.height, ExtendedColorType::L8)?;
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_plane_extracts_known_bits() {
        // 2 个 RGBA 像素：R 通道分别为 0b1010_1010(=0xAA) 与 0b0101_0101(=0x55)
        let pixels = vec![
            0xAA, 0, 0, 255, // px0 R=10101010
            0x55, 0, 0, 255, // px1 R=01010101
        ];
        // bit0(LSB)：px0=0→黑，px1=1→白
        let lsb = bit_plane(&pixels, 2, 1, 0, 0);
        assert_eq!(lsb, vec![0, 255]);
        // bit7(MSB)：px0=1→白，px1=0→黑
        let msb = bit_plane(&pixels, 2, 1, 0, 7);
        assert_eq!(msb, vec![255, 0]);
        // bit1：px0=1，px1=0
        let b1 = bit_plane(&pixels, 2, 1, 0, 1);
        assert_eq!(b1, vec![255, 0]);
    }

    #[test]
    fn bit_plane_length_matches_pixel_count() {
        let w = 4u32;
        let h = 3u32;
        let pixels = vec![0u8; (w * h * 4) as usize];
        let plane = bit_plane(&pixels, w, h, 2, 3);
        assert_eq!(plane.len(), (w * h) as usize);
    }

    #[test]
    fn bit_plane_is_channel_specific() {
        // 只在 G 通道置奇数（LSB=1），R 通道全偶数（LSB=0）
        let mut pixels = vec![0u8; 2 * 4];
        pixels[1] = 3; // px0 G
        pixels[5] = 7; // px1 G
        let g = bit_plane(&pixels, 2, 1, 1, 0);
        let r = bit_plane(&pixels, 2, 1, 0, 0);
        assert_eq!(g, vec![255, 255]);
        assert_eq!(r, vec![0, 0]);
    }

    #[test]
    fn all_odd_values_fill_lsb_white() {
        let pixels = vec![1u8, 0, 0, 255, 3, 0, 0, 255, 255, 0, 0, 255];
        let lsb = bit_plane(&pixels, 3, 1, 0, 0);
        assert_eq!(lsb, vec![255, 255, 255]);
    }

    #[test]
    fn all_even_values_fill_lsb_black() {
        let pixels = vec![0u8, 0, 0, 255, 2, 0, 0, 255, 254, 0, 0, 255];
        let lsb = bit_plane(&pixels, 3, 1, 0, 0);
        assert_eq!(lsb, vec![0, 0, 0]);
    }

    #[test]
    fn parse_bits_all_and_singletons() {
        assert_eq!(parse_bits("all"), vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(parse_bits(""), vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(parse_bits("3"), vec![3]);
        assert_eq!(parse_bits("0,7"), vec![0, 7]);
    }

    #[test]
    fn parse_bits_dedupes_sorts_and_filters() {
        // 去重、升序、过滤 ≥8 的非法值
        assert_eq!(parse_bits("7,1,7,9,2"), vec![1, 2, 7]);
        // 全部非法时回退为 0..8
        assert_eq!(parse_bits("9,12"), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }
}
