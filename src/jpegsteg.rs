//! JPEG DCT 域隐写盲检测（针对 F5 / steghide 等对 chi-square 免疫的算法）。
//!
//! F5 用"系数减 1 + 矩阵编码"嵌入、steghide 用图论交换保持一阶直方图，二者都
//! 无法靠 LSB/卡方确定性识别。学术界主流做法是**校准攻击**（Fridrich/Pevný）：把
//! 待测 JPEG 解码后裁掉边缘若干行/列，再用**原图同一张量化表**重压缩，迫使 8×8
//! 网格错位而量化矩阵不变，得到近似原始载体的参考图，比较两者的 DCT 统计差异。
//! 本模块在无训练分类器的前提下，用校准后的零系数占比、直方图散度、块间共现、
//! 块间变化、块效应五维指标做"显著性门控"启发式评分。
//!
//! 能力红线：输出的是**可疑度而非确定结论**，不提取明文、不保证算法归因准确，
//! 阈值为经验值，存在假阳/假阴，仅供研判。无训练富模型分类器时，对保持一阶统计
//! 且不增零的高纹理低嵌入率 steghide，单图启发式仍可能无法与干净图区分（学界公认难点）。

use libjpeg_turbo_rs::{
    PixelFormat, Subsampling, decompress, encode::pipeline::compress_custom_quant,
    read_coefficients,
};

/// 直方图统计的系数区间 [-HIST_BOUND, HIST_BOUND]，区间外并入两端 bin
const HIST_BOUND: i16 = 16;
/// 校准重压缩的兜底质量因子；当原图量化表 slot 缺失回退标准表时才真正生效，
/// 正常路径下量化表由 `compress_custom_quant` 显式提供，会覆盖此质量因子。
const CALIB_QUALITY: u8 = 92;
/// 校准裁剪的边缘像素数（迫使 8x8 网格错位）
const CALIB_CROP: usize = 4;

/// 可疑度分级
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 未发现明显异常
    Clean,
    /// 低度可疑
    Low,
    /// 中度可疑
    Medium,
    /// 高度可疑
    High,
}

impl Verdict {
    pub fn as_cn(self) -> &'static str {
        match self {
            Verdict::Clean => "未发现明显异常",
            Verdict::Low => "低度可疑",
            Verdict::Medium => "中度可疑",
            Verdict::High => "高度可疑",
        }
    }
}

/// 启发式算法归因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmGuess {
    /// 倾向 F5（零系数收缩特征明显）
    F5,
    /// 倾向 steghide（一阶统计保持、块效应/高阶偏离）
    Steghide,
    /// 证据不足，不做归因
    Unknown,
}

impl AlgorithmGuess {
    pub fn as_label(self) -> &'static str {
        match self {
            AlgorithmGuess::F5 => "F5",
            AlgorithmGuess::Steghide => "steghide",
            AlgorithmGuess::Unknown => "不确定",
        }
    }
}

/// 盲检测报告
#[derive(Debug, Clone)]
pub struct StegoReport {
    /// 参与统计的亮度 AC 系数总数
    pub ac_total: usize,
    /// 待测图 AC 零值占比
    pub zero_ratio: f64,
    /// 校准参考图 AC 零值占比
    pub calib_zero_ratio: f64,
    /// 待测 vs 校准一阶直方图的归一化 L1 散度（0~2）
    pub histogram_divergence: f64,
    /// 块间相邻系数共现矩阵（Fridrich 公式 8）的校准 L1 散度，对 steghide 敏感
    pub cooccurrence_divergence: f64,
    /// 块间变化（公式 5）相对校准基线的相对偏离率
    pub variation_rel: f64,
    /// 块效应 B1（α=1）相对校准基线的相对偏离率
    pub blockiness_rel: f64,
    /// 综合可疑度 0..=100
    pub score: u8,
    /// 可疑度分级
    pub verdict: Verdict,
    /// 启发式算法归因
    pub guess: AlgorithmGuess,
    /// 校准是否成功（图过小无法裁剪时为 false，相关指标可信度下降）
    pub calibrated: bool,
}

/// 收集亮度分量（通常为 components[0]）的全部 AC 系数，展平为一维序列。
fn collect_luma_ac(coeffs: &libjpeg_turbo_rs::JpegCoefficients) -> Vec<i16> {
    let Some(component) = coeffs.components.first() else {
        return Vec::new();
    };
    let mut ac = Vec::with_capacity(component.blocks.len() * 63);
    for block in &component.blocks {
        ac.extend_from_slice(&block[1..64]); // block[0] 为 DC，跳过
    }
    ac
}

/// 统计 AC 系数零值占比。
fn zero_ratio(ac: &[i16]) -> f64 {
    if ac.is_empty() {
        return 0.0;
    }
    let zeros = ac.iter().filter(|&&c| c == 0).count();
    zeros as f64 / ac.len() as f64
}

/// 构建区间 [-HIST_BOUND, HIST_BOUND] 的频度直方图，越界值并入两端 bin。
/// 返回长度 `2*HIST_BOUND+1` 的计数数组，bin 索引 0 对应 -HIST_BOUND。
fn histogram(ac: &[i16]) -> Vec<usize> {
    let n = (HIST_BOUND as usize) * 2 + 1;
    let mut hist = vec![0usize; n];
    for &c in ac {
        let clamped = c.clamp(-HIST_BOUND, HIST_BOUND);
        let idx = (clamped + HIST_BOUND) as usize;
        hist[idx] += 1;
    }
    hist
}

/// 两个直方图的归一化 L1 散度：先转概率分布再逐 bin 求绝对差之和。
fn hist_l1(a: &[usize], b: &[usize]) -> f64 {
    let sum_a: usize = a.iter().sum();
    let sum_b: usize = b.iter().sum();
    if sum_a == 0 || sum_b == 0 || a.len() != b.len() {
        return 0.0;
    }
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x as f64 / sum_a as f64 - y as f64 / sum_b as f64).abs())
        .sum()
}

/// 相邻 8x8 块同位置 DCT 系数的共现矩阵（Fridrich 公式 8，块间 inter-block）。
///
/// 与块内 zigzag 相邻不同，这里统计空间相邻块（水平/垂直）在**同一 DCT 模式**
/// 位置上的系数对 `(s,t)`，这是对 steghide 图论交换更敏感的块间依赖特征。
/// 系数截断到 [-COOC_BOUND, COOC_BOUND]，返回归一化概率（和为 1）。
const COOC_BOUND: i16 = 2;

fn inter_cooccurrence(blocks: &[[i16; 64]], blocks_x: usize, blocks_y: usize) -> Vec<f64> {
    let dim = (COOC_BOUND as usize) * 2 + 1;
    let mut matrix = vec![0u64; dim * dim];
    let mut total = 0u64;

    // 闭包：累加一个相邻块对的 64 个同位置系数对
    let accumulate = |a: &[i16; 64], b: &[i16; 64], m: &mut Vec<u64>, t: &mut u64| {
        for mode in 0..64 {
            let (x, y) = (a[mode], b[mode]);
            if (-COOC_BOUND..=COOC_BOUND).contains(&x) && (-COOC_BOUND..=COOC_BOUND).contains(&y) {
                let ia = (x + COOC_BOUND) as usize;
                let ib = (y + COOC_BOUND) as usize;
                m[ia * dim + ib] += 1;
                *t += 1;
            }
        }
    };

    // 水平相邻块 (x, x+1)
    for y in 0..blocks_y {
        for x in 0..blocks_x.saturating_sub(1) {
            let a = &blocks[y * blocks_x + x];
            let b = &blocks[y * blocks_x + x + 1];
            accumulate(a, b, &mut matrix, &mut total);
        }
    }
    // 垂直相邻块 (y, y+1)
    for y in 0..blocks_y.saturating_sub(1) {
        for x in 0..blocks_x {
            let a = &blocks[y * blocks_x + x];
            let b = &blocks[(y + 1) * blocks_x + x];
            accumulate(a, b, &mut matrix, &mut total);
        }
    }

    matrix
        .iter()
        .map(|&c| {
            if total == 0 {
                0.0
            } else {
                c as f64 / total as f64
            }
        })
        .collect()
}

/// 两个概率向量的 L1 距离（用于归一化共现矩阵比较，范围 0~2）。
fn vec_l1(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).sum()
}

/// 块间系数变化（Fridrich 公式 5 variation V）：相邻块同位置系数差绝对值的均值。
/// steghide 的图论交换与 F5 的系数收缩都会改变块间依赖，该标量对二者敏感。
fn inter_block_variation(blocks: &[[i16; 64]], blocks_x: usize, blocks_y: usize) -> f64 {
    let mut total = 0u64;
    let mut count = 0u64;
    let add_pair = |a: &[i16; 64], b: &[i16; 64], t: &mut u64, c: &mut u64| {
        for mode in 0..64 {
            *t += (a[mode] as i64 - b[mode] as i64).unsigned_abs();
            *c += 1;
        }
    };
    for y in 0..blocks_y {
        for x in 0..blocks_x.saturating_sub(1) {
            add_pair(
                &blocks[y * blocks_x + x],
                &blocks[y * blocks_x + x + 1],
                &mut total,
                &mut count,
            );
        }
    }
    for y in 0..blocks_y.saturating_sub(1) {
        for x in 0..blocks_x {
            add_pair(
                &blocks[y * blocks_x + x],
                &blocks[(y + 1) * blocks_x + x],
                &mut total,
                &mut count,
            );
        }
    }
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

/// 计算灰度像素缓冲在 8x8 块边界处的不连续度（Fridrich 公式 6 块效应 B_α）。
///
/// 同时统计水平边界（列 x=8k 处左右像素差）与垂直边界（行 y=8k 处上下像素差），
/// `alpha` 为幂次：α=1 给 B1，α=2 给 B2（对强跳变更敏感）。结果为所有边界的均值，
/// 纯像素函数，输入手工缓冲即可单测。
fn blockiness_gray(pixels: &[u8], width: usize, height: usize, alpha: u32) -> f64 {
    let mut total = 0.0f64;
    let mut count = 0.0f64;
    // 水平方向块边界（跨列）
    for y in 0..height {
        let row = y * width;
        for x in 1..width {
            if x % 8 == 0 {
                let d = pixels[row + x].abs_diff(pixels[row + x - 1]) as f64;
                total += d.powi(alpha as i32);
                count += 1.0;
            }
        }
    }
    // 垂直方向块边界（跨行）
    for x in 0..width {
        for y in 1..height {
            if y % 8 == 0 {
                let d = pixels[y * width + x].abs_diff(pixels[(y - 1) * width + x]) as f64;
                total += d.powi(alpha as i32);
                count += 1.0;
            }
        }
    }
    if count == 0.0 { 0.0 } else { total / count }
}

/// 校准攻击：解码 → 裁掉左上 CALIB_CROP 行列 → **用原图同一张量化表**重压缩。
///
/// Fridrich 校准要求参考图与待测图共享量化矩阵，仅让 8×8 网格错位，这样两者的
/// DCT 统计差才反映隐写扰动而非二次量化噪声。`src_coeffs` 提供原图量化表（自然序，
/// 与 `compress_custom_quant` 入参约定一致）。
/// 返回（校准图系数，重压缩 JPEG 字节，像素格式）；图过小无法安全裁剪时返回 None。
fn calibrate(
    jpeg: &[u8],
    src_coeffs: &libjpeg_turbo_rs::JpegCoefficients,
) -> Option<(libjpeg_turbo_rs::JpegCoefficients, Vec<u8>, PixelFormat)> {
    let image = decompress(jpeg).ok()?;
    let bpp = image.pixel_format.bytes_per_pixel();
    let width = image.width;
    let height = image.height;
    if width <= CALIB_CROP + 16 || height <= CALIB_CROP + 16 {
        return None;
    }
    let new_w = width - CALIB_CROP;
    let new_h = height - CALIB_CROP;

    // 按像素格式逐像素重排裁剪后的缓冲
    let format = image.pixel_format;
    let mut cropped = Vec::with_capacity(new_w * new_h * bpp);
    for y in CALIB_CROP..height {
        for x in CALIB_CROP..width {
            let src = (y * width + x) * bpp;
            cropped.extend_from_slice(&image.data[src..src + bpp]);
        }
    }

    let subsampling = if format == PixelFormat::Grayscale {
        Subsampling::S444
    } else {
        Subsampling::S420
    };

    // 复用原图 slot0(luma)/slot1(chroma) 量化表，未提供的 slot 留空回退标准表；
    // quality 仅在对应 slot 为 None 时生效，自定义表会覆盖它。
    let mut custom_quant: [Option<[u16; 64]>; 4] = [None; 4];
    for (slot, table) in src_coeffs.quant_tables.iter().enumerate().take(2) {
        custom_quant[slot] = Some(*table);
    }
    let recompressed = compress_custom_quant(
        &cropped,
        new_w,
        new_h,
        format,
        CALIB_QUALITY,
        subsampling,
        &custom_quant,
    )
    .ok()?;
    let calib_coeffs = read_coefficients(&recompressed).ok()?;
    Some((calib_coeffs, recompressed, format))
}

/// 从 JPEG 字节解码并取首通道（灰度/R），返回块效应 B1（α=1）与 B2（α=2）。
fn blockiness_of_jpeg(jpeg: &[u8]) -> (f64, f64) {
    let Ok(image) = decompress(jpeg) else {
        return (0.0, 0.0);
    };
    let bpp = image.pixel_format.bytes_per_pixel();
    let gray: Vec<u8> = image.data.chunks_exact(bpp).map(|px| px[0]).collect();
    let b1 = blockiness_gray(&gray, image.width, image.height, 1);
    let b2 = blockiness_gray(&gray, image.width, image.height, 2);
    (b1, b2)
}

/// 相对偏离率：`|test - base| / max(base, eps)`，消除不同图的尺度差异。
fn relative_delta(test: f64, base: f64) -> f64 {
    (test - base).abs() / base.abs().max(1e-9)
}

/// 由各项校准偏离指标，经显著性门控计算综合可疑度、分级与启发式归因。纯函数便于单测。
///
/// 全部输入采用**相对偏离率**或归一化散度，以适配不同纹理/质量的图：
/// - `zero_lift`：零占比绝对升高量（F5 收缩的直接信号，本身是比例量）；
/// - `hist_div`：一阶直方图归一化 L1 散度（0~2）；
/// - `cooc_div`：块间共现概率矩阵 L1 散度（0~2，对 steghide 敏感）；
/// - `var_rel`：块间变化 V 的相对偏离率；
/// - `block_rel`：块效应 B1 的相对偏离率。
#[allow(clippy::too_many_arguments)]
fn score_report(
    zero_lift: f64,
    hist_div: f64,
    cooc_div: f64,
    var_rel: f64,
    block_rel: f64,
) -> (u8, Verdict, AlgorithmGuess) {
    // 经验阈值（无分类器，仅作启发式），依据同量化表校准后的真实样本对照标定。
    // 关键设计是"显著性门控"：每一维只有越过阈值才计分，亚阈值的校准噪声一律记 0，
    // 避免多个不显著的微小偏离累加成假阳性（旧加权模型在平滑干净图上正是因此误报）。
    const ZERO_LIFT_THRESHOLD: f64 = 0.02;
    const HIST_DIV_THRESHOLD: f64 = 0.10;
    const COOC_DIV_THRESHOLD: f64 = 0.06;
    const VAR_REL_THRESHOLD: f64 = 0.30;
    const BLOCK_REL_THRESHOLD: f64 = 0.15;

    // 门控激活后的满分权重，合计 100：零收缩 30（F5 决定性证据）、共现 25、
    // 一阶 15、变化 15、块效应 15。
    const ZERO_WEIGHT: f64 = 30.0;
    const HIST_WEIGHT: f64 = 15.0;
    const COOC_WEIGHT: f64 = 25.0;
    const VAR_WEIGHT: f64 = 15.0;
    const BLOCK_WEIGHT: f64 = 15.0;

    // 单维得分：未越阈记 0；越阈后按超阈强度给 0.5~1.0 倍权重
    // （恰在阈值处给半权，达到 2 倍阈值给满权），让结论同时反映"是否异常"与"异常多强"。
    let gated = |value: f64, threshold: f64, weight: f64| -> f64 {
        let ratio = value / threshold;
        if ratio < 1.0 {
            0.0
        } else {
            let intensity = (ratio.min(2.0) / 2.0) + 0.5;
            weight * intensity
        }
    };

    let zero_score = gated(zero_lift.max(0.0), ZERO_LIFT_THRESHOLD, ZERO_WEIGHT);
    let hist_score = gated(hist_div, HIST_DIV_THRESHOLD, HIST_WEIGHT);
    let cooc_score = gated(cooc_div, COOC_DIV_THRESHOLD, COOC_WEIGHT);
    let var_score = gated(var_rel, VAR_REL_THRESHOLD, VAR_WEIGHT);
    let block_score = gated(block_rel, BLOCK_REL_THRESHOLD, BLOCK_WEIGHT);

    let score = (zero_score + hist_score + cooc_score + var_score + block_score)
        .round()
        .clamp(0.0, 100.0) as u8;

    let verdict = match score {
        0..=24 => Verdict::Clean,
        25..=49 => Verdict::Low,
        50..=74 => Verdict::Medium,
        _ => Verdict::High,
    };

    // 启发式归因：
    // - 零占比显著升高（收缩）是 F5 的决定性证据，即使块间特征同时异常也优先判 F5；
    // - 零占比正常而块间依赖（共现/变化）越阈时判 steghide（图论交换保持一阶统计）。
    let guess = if zero_lift >= ZERO_LIFT_THRESHOLD {
        AlgorithmGuess::F5
    } else if cooc_div >= COOC_DIV_THRESHOLD || var_rel >= VAR_REL_THRESHOLD {
        AlgorithmGuess::Steghide
    } else {
        AlgorithmGuess::Unknown
    };

    (score, verdict, guess)
}

/// 盲检测入口：解析 JPEG、做校准并产出报告。
pub fn analyze(jpeg: &[u8]) -> anyhow::Result<StegoReport> {
    let coeffs =
        read_coefficients(jpeg).map_err(|e| anyhow::anyhow!("解析 JPEG DCT 系数失败：{e}"))?;
    let ac = collect_luma_ac(&coeffs);
    let ac_total = ac.len();
    let zero_frac = zero_ratio(&ac);
    let hist = histogram(&ac);
    let luma = coeffs.components.first();
    let (test_bx, test_by, test_blocks) = match luma {
        Some(c) => (c.blocks_x, c.blocks_y, c.blocks.as_slice()),
        None => (0usize, 0usize, &[][..]),
    };
    let test_cooc = inter_cooccurrence(test_blocks, test_bx, test_by);
    let test_var = inter_block_variation(test_blocks, test_bx, test_by);
    let (test_b1, _test_b2) = blockiness_of_jpeg(jpeg);

    let mut report = StegoReport {
        ac_total,
        zero_ratio: zero_frac,
        calib_zero_ratio: 0.0,
        histogram_divergence: 0.0,
        cooccurrence_divergence: 0.0,
        variation_rel: 0.0,
        blockiness_rel: 0.0,
        score: 0,
        verdict: Verdict::Clean,
        guess: AlgorithmGuess::Unknown,
        calibrated: false,
    };

    // 校准可用时计算相对基线的偏离；不可用则降级为仅基于零占比的弱判断
    if let Some((calib_coeffs, recompressed, _format)) = calibrate(jpeg, &coeffs) {
        let calib_ac = collect_luma_ac(&calib_coeffs);
        let calib_zero = zero_ratio(&calib_ac);
        let calib_hist = histogram(&calib_ac);
        let divergence = hist_l1(&hist, &calib_hist);

        let calib_luma = calib_coeffs.components.first();
        let (calib_bx, calib_by, calib_blocks) = match calib_luma {
            Some(c) => (c.blocks_x, c.blocks_y, c.blocks.as_slice()),
            None => (0usize, 0usize, &[][..]),
        };
        let calib_cooc = inter_cooccurrence(calib_blocks, calib_bx, calib_by);
        let cooc_div = vec_l1(&test_cooc, &calib_cooc);
        let calib_var = inter_block_variation(calib_blocks, calib_bx, calib_by);
        let var_rel = relative_delta(test_var, calib_var);
        let (calib_b1, _calib_b2) = blockiness_of_jpeg(&recompressed);
        let block_rel = relative_delta(test_b1, calib_b1);

        report.calibrated = true;
        report.calib_zero_ratio = calib_zero;
        report.histogram_divergence = divergence;
        report.cooccurrence_divergence = cooc_div;
        report.variation_rel = var_rel;
        report.blockiness_rel = block_rel;

        let (score, verdict, guess) = score_report(
            zero_frac - calib_zero,
            divergence,
            cooc_div,
            var_rel,
            block_rel,
        );
        report.score = score;
        report.verdict = verdict;
        report.guess = guess;
    } else {
        // 降级：无校准基线，以 0.5 为经验零占比中位点给保守评分，不做归因
        let (score, verdict, guess) = score_report(zero_frac - 0.5, 0.0, 0.0, 0.0, 0.0);
        report.score = score;
        report.verdict = verdict;
        report.guess = guess;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ratio_basic() {
        assert_eq!(zero_ratio(&[]), 0.0);
        assert_eq!(zero_ratio(&[0, 0, 1, -1, 2]), 0.4);
        assert_eq!(zero_ratio(&[1, 2, 3]), 0.0);
        assert_eq!(zero_ratio(&[0, 0]), 1.0);
    }

    #[test]
    fn histogram_clamps_out_of_range() {
        let ac = vec![-16i16, -16, 16, 100, -100, 0];
        let h = histogram(&ac);
        let n = HIST_BOUND as usize * 2 + 1;
        assert_eq!(h.len(), n);
        // -100 与 -16 都并入最低 bin（索引 0），共 3 个
        assert_eq!(h[0], 3);
        // 100 与 16 并入最高 bin，共 2 个
        assert_eq!(h[n - 1], 2);
        // 0 位于中间 bin
        assert_eq!(h[HIST_BOUND as usize], 1);
    }

    #[test]
    fn hist_l1_identical_is_zero() {
        let a = vec![1usize, 2, 3, 4];
        assert_eq!(hist_l1(&a, &a), 0.0);
    }

    #[test]
    fn hist_l1_known_difference() {
        // 两个完全不重叠的分布，归一化 L1 散度为 2
        let a = vec![10usize, 0];
        let b = vec![0usize, 10];
        assert!((hist_l1(&a, &b) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn blockiness_detects_grid_boundary_jump() {
        // 16x1 图，列 8 边界处制造 0->200 的跳变
        let mut pixels = vec![0u8; 16];
        pixels[8] = 200;
        let b = blockiness_gray(&pixels, 16, 1, 1);
        assert!(b > 50.0, "跨块跳变应产生高块效应，实际 {b}");
    }

    #[test]
    fn blockiness_alpha2_amplifies_jump() {
        let mut pixels = vec![0u8; 16];
        pixels[8] = 200;
        let b1 = blockiness_gray(&pixels, 16, 1, 1);
        let b2 = blockiness_gray(&pixels, 16, 1, 2);
        // 平方矩对大跳变更敏感，B2 应明显大于 B1
        assert!(b2 > b1);
    }

    #[test]
    fn blockiness_smooth_image_low() {
        // 全平滑（同值）图块效应为 0
        let pixels = vec![100u8; 32 * 4];
        assert_eq!(blockiness_gray(&pixels, 32, 4, 1), 0.0);
        assert_eq!(blockiness_gray(&pixels, 32, 4, 2), 0.0);
    }

    #[test]
    fn inter_cooccurrence_counts_same_position_neighbor_blocks() {
        // 两个水平相邻块，所有 64 个同位置系数都取 1，故全部块对落入 (1,1) bin
        let blocks = vec![[1i16; 64]; 2];
        // 2 块排成 1 行 2 列，blocks_x=2 blocks_y=1
        let m = inter_cooccurrence(&blocks, 2, 1);
        let dim = (COOC_BOUND as usize) * 2 + 1;
        let idx = |s: i16, t: i16| -> usize {
            ((s + COOC_BOUND) as usize) * dim + (t + COOC_BOUND) as usize
        };
        // 全部 64 个同位置对都是 (1,1)，归一化后该 bin 概率为 1
        assert!((m[idx(1, 1)] - 1.0).abs() < 1e-9);
        let total: f64 = m.iter().sum();
        assert!((total - 1.0).abs() < 1e-9, "概率矩阵应归一化");
    }

    #[test]
    fn inter_cooccurrence_identical_vectors_l1_zero() {
        let blocks = vec![[1i16; 64]; 4];
        let m = inter_cooccurrence(&blocks, 2, 2);
        assert!((vec_l1(&m, &m) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn variation_zero_for_identical_blocks() {
        // 所有块相同，相邻块同位置差恒为 0
        let blocks = vec![[5i16; 64]; 4];
        assert_eq!(inter_block_variation(&blocks, 2, 2), 0.0);
    }

    #[test]
    fn variation_detects_neighbor_difference() {
        // 两个水平相邻块，仅 mode 0 相差 2，其余相同
        let mut blocks = vec![[0i16; 64]; 2];
        blocks[1][0] = 2;
        let v = inter_block_variation(&blocks, 2, 1);
        // 仅 1 个非零差（值 2），共 64 对
        assert!((v - 2.0 / 64.0).abs() < 1e-9);
    }

    #[test]
    fn relative_delta_basic() {
        assert!((relative_delta(110.0, 100.0) - 0.1).abs() < 1e-9);
        // 基线为 0 时不除零
        assert!(relative_delta(1.0, 0.0).is_finite());
    }

    #[test]
    fn score_strong_shrinkage_points_to_f5() {
        // 零占比 lift 远超门限（F5 收缩）、一阶散度强，块间特征温和 → 零收缩主导，
        // 归因 F5，且评分显著高于干净基线。
        let (score, verdict, guess) = score_report(0.30, 0.6, 0.02, 0.05, 0.02);
        assert_eq!(guess, AlgorithmGuess::F5);
        assert!(
            matches!(verdict, Verdict::Medium | Verdict::High),
            "F5 强信号应至少中度可疑，实际 {score}"
        );
        // 与全零干净基线对比应有明显差距
        let (clean_score, _, clean_guess) = score_report(0.0, 0.0, 0.0, 0.0, 0.0);
        assert!(score > clean_score);
        assert_eq!(clean_guess, AlgorithmGuess::Unknown);
    }

    #[test]
    fn score_interblock_dominant_points_to_steghide() {
        // 零占比/一阶正常，但块间共现与变化越过门限 → 倾向 steghide
        let (score, verdict, guess) = score_report(0.0, 0.05, 0.2, 0.3, 0.05);
        assert_eq!(guess, AlgorithmGuess::Steghide);
        assert!(score >= 50, "块间强偏离应至少中度可疑，实际 {score}");
        assert_ne!(verdict, Verdict::Clean);
    }

    #[test]
    fn score_subthreshold_noise_does_not_accumulate() {
        // 显著性门控：每一维都停在门限以下（量级取自真实平滑干净图），
        // 即使五维都有微小偏离也必须记 0，杜绝亚阈值噪声累加成假阳性。
        let (score, verdict, guess) = score_report(0.001, 0.02, 0.022, 0.15, 0.13);
        assert_eq!(score, 0);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(guess, AlgorithmGuess::Unknown);
    }

    #[test]
    fn score_clean_baseline() {
        let (score, verdict, guess) = score_report(0.0, 0.0, 0.0, 0.0, 0.0);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(guess, AlgorithmGuess::Unknown);
        assert_eq!(score, 0);
    }

    #[test]
    fn verdict_labels_are_chinese() {
        assert_eq!(Verdict::High.as_cn(), "高度可疑");
        assert_eq!(AlgorithmGuess::F5.as_label(), "F5");
        assert_eq!(AlgorithmGuess::Steghide.as_label(), "steghide");
    }
}
