//! JPEG DCT 域隐写盲检测（针对 F5 / steghide 等对 chi-square 免疫的算法）。
//!
//! F5 用"系数减 1 + 矩阵编码"嵌入、steghide 用图论交换保持一阶直方图，二者都
//! 无法靠 LSB/卡方确定性识别。学术界主流做法是**校准攻击**：把待测 JPEG 解码后
//! 裁掉边缘若干行/列再同质量重压缩，得到近似原始载体的参考图，比较两者的 DCT
//! 统计差异。本模块在无训练分类器的前提下，用校准后的零系数占比、直方图散度、
//! 块效应偏离等指标做启发式评分。
//!
//! 能力红线：输出的是**可疑度而非确定结论**，不提取明文、不保证算法归因准确，
//! 阈值为经验值，存在假阳/假阴，仅供研判。

use libjpeg_turbo_rs::{PixelFormat, Subsampling, compress, decompress, read_coefficients};

/// 直方图统计的系数区间 [-HIST_BOUND, HIST_BOUND]，区间外并入两端 bin
const HIST_BOUND: i16 = 16;
/// 校准重压缩固定质量（与样本生成质量保持独立，仅用于构造参考载体）
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
    /// 待测 vs 校准直方图的归一化 L1 散度（0~2）
    pub histogram_divergence: f64,
    /// 相邻 AC 系数共现矩阵的校准 L1 散度（二阶特征，对 steghide 敏感）
    pub cooccurrence_divergence: f64,
    /// 块效应相对校准基线的偏离量
    pub blockiness_delta: f64,
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

/// 相邻 AC 系数共现矩阵（二阶统计），对保持一阶直方图的 steghide 更敏感。
///
/// 统计每个 8x8 块内 zigzag 相邻位置 `(ac[i], ac[i+1])`（仅 block[1..64]，
/// 不跨块）的联合出现频度，系数先截断到 [-COOC_BOUND, COOC_BOUND]。
/// 返回展平的一维计数，索引 = `(a+BOUND)*(2*BOUND+1) + (b+BOUND)`。
const COOC_BOUND: i16 = 4;

fn cooccurrence(blocks: &[[i16; 64]]) -> Vec<usize> {
    let dim = (COOC_BOUND as usize) * 2 + 1;
    let mut matrix = vec![0usize; dim * dim];
    for block in blocks {
        for pair in block[1..64].windows(2) {
            let a = pair[0].clamp(-COOC_BOUND, COOC_BOUND) + COOC_BOUND;
            let b = pair[1].clamp(-COOC_BOUND, COOC_BOUND) + COOC_BOUND;
            matrix[(a as usize) * dim + b as usize] += 1;
        }
    }
    matrix
}

/// 共现矩阵的归一化 L1 散度（与 hist_l1 同口径，复用于二阶分布比较）。
fn cooc_l1(a: &[usize], b: &[usize]) -> f64 {
    hist_l1(a, b)
}

/// 计算灰度像素缓冲在 8 像素网格边界处的平均不连续度（块效应）。
///
/// 仅统计水平方向跨块边界（列号为 8 的倍数）相邻像素的绝对差，取均值。
/// 纯像素函数，输入手工缓冲即可单测。
fn blockiness_gray(pixels: &[u8], width: usize, height: usize) -> f64 {
    if width < 9 || height == 0 {
        return 0.0;
    }
    let mut total = 0u64;
    let mut count = 0u64;
    for y in 0..height {
        let row = y * width;
        for x in 8..width {
            if x % 8 == 0 {
                total += pixels[row + x].abs_diff(pixels[row + x - 1]) as u64;
                count += 1;
            }
        }
    }
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

/// 校准攻击：解码 → 裁掉左上 CALIB_CROP 行列 → 同质量重压缩。
/// 返回（校准图系数，重压缩 JPEG 字节，像素格式）；图过小无法安全裁剪时返回 None。
fn calibrate(jpeg: &[u8]) -> Option<(libjpeg_turbo_rs::JpegCoefficients, Vec<u8>, PixelFormat)> {
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
    let recompressed = compress(&cropped, new_w, new_h, format, CALIB_QUALITY, subsampling).ok()?;
    let calib_coeffs = read_coefficients(&recompressed).ok()?;
    Some((calib_coeffs, recompressed, format))
}

/// 从 JPEG 字节解码并取首通道（灰度/R）计算块效应。
fn blockiness_of_jpeg(jpeg: &[u8]) -> f64 {
    let Ok(image) = decompress(jpeg) else {
        return 0.0;
    };
    let bpp = image.pixel_format.bytes_per_pixel();
    let gray: Vec<u8> = image.data.chunks_exact(bpp).map(|px| px[0]).collect();
    blockiness_gray(&gray, image.width, image.height)
}

/// 由各项校准偏离指标计算综合可疑度、分级与启发式归因。纯函数便于单测。
///
/// 参数均为"待测相对校准基线"的偏离量：
/// - `zero_lift`：零占比升高量（待测 - 校准），F5 收缩会使其显著为正；
/// - `hist_div`：一阶直方图归一化 L1 散度；
/// - `cooc_div`：相邻系数共现矩阵 L1 散度（二阶，对保持一阶统计的 steghide 敏感）；
/// - `block_delta`：块效应偏离的绝对值。
#[allow(clippy::too_many_arguments)]
fn score_report(
    zero_lift: f64,
    hist_div: f64,
    cooc_div: f64,
    block_delta: f64,
) -> (u8, Verdict, AlgorithmGuess) {
    // 经验阈值（无分类器，仅作启发式）：各项偏离超过阈值才计分
    const ZERO_LIFT_THRESHOLD: f64 = 0.03;
    const HIST_DIV_THRESHOLD: f64 = 0.15;
    const COOC_DIV_THRESHOLD: f64 = 0.10;
    const BLOCK_DELTA_THRESHOLD: f64 = 1.0;

    // 四个维度加权，归一到 0..=100：零占比 30、一阶 20、二阶共现 30、块效应 20
    let zero_score = (zero_lift.max(0.0) / ZERO_LIFT_THRESHOLD).min(1.0) * 30.0;
    let hist_score = (hist_div / HIST_DIV_THRESHOLD).min(1.0) * 20.0;
    let cooc_score = (cooc_div / COOC_DIV_THRESHOLD).min(1.0) * 30.0;
    let block_score = (block_delta.abs() / BLOCK_DELTA_THRESHOLD).min(1.0) * 20.0;
    let score = (zero_score + hist_score + cooc_score + block_score)
        .round()
        .clamp(0.0, 100.0) as u8;

    let verdict = match score {
        0..=24 => Verdict::Clean,
        25..=49 => Verdict::Low,
        50..=74 => Verdict::Medium,
        _ => Verdict::High,
    };

    // 启发式归因：零系数收缩主导判 F5；一阶保持但二阶共现偏离主导判 steghide
    let guess = if zero_lift >= ZERO_LIFT_THRESHOLD && zero_score >= cooc_score {
        AlgorithmGuess::F5
    } else if cooc_div >= COOC_DIV_THRESHOLD && cooc_score > zero_score {
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
    let test_blocks: &[[i16; 64]] = match coeffs.components.first() {
        Some(c) => &c.blocks,
        None => &[],
    };
    let test_cooc = cooccurrence(test_blocks);
    let test_blockiness = blockiness_of_jpeg(jpeg);

    let mut report = StegoReport {
        ac_total,
        zero_ratio: zero_frac,
        calib_zero_ratio: 0.0,
        histogram_divergence: 0.0,
        cooccurrence_divergence: 0.0,
        blockiness_delta: 0.0,
        score: 0,
        verdict: Verdict::Clean,
        guess: AlgorithmGuess::Unknown,
        calibrated: false,
    };

    // 校准可用时计算相对基线的偏离；不可用则降级为仅基于零占比的弱判断
    if let Some((calib_coeffs, recompressed, _format)) = calibrate(jpeg) {
        let calib_ac = collect_luma_ac(&calib_coeffs);
        let calib_zero = zero_ratio(&calib_ac);
        let calib_hist = histogram(&calib_ac);
        let divergence = hist_l1(&hist, &calib_hist);
        let calib_blocks: &[[i16; 64]] = calib_coeffs
            .components
            .first()
            .map(|c| &c.blocks[..])
            .unwrap_or(&[]);
        let calib_cooc = cooccurrence(calib_blocks);
        let cooc_div = cooc_l1(&test_cooc, &calib_cooc);
        let calib_blockiness = blockiness_of_jpeg(&recompressed);
        let block_delta = test_blockiness - calib_blockiness;

        report.calibrated = true;
        report.calib_zero_ratio = calib_zero;
        report.histogram_divergence = divergence;
        report.cooccurrence_divergence = cooc_div;
        report.blockiness_delta = block_delta;

        let (score, verdict, guess) =
            score_report(zero_frac - calib_zero, divergence, cooc_div, block_delta);
        report.score = score;
        report.verdict = verdict;
        report.guess = guess;
    } else {
        // 降级：无校准基线，以 0.5 为经验零占比中位点给保守评分，不做归因
        let (score, verdict, guess) = score_report(zero_frac - 0.5, 0.0, 0.0, 0.0);
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
        let b = blockiness_gray(&pixels, 16, 1);
        assert!(b > 50.0, "跨块跳变应产生高块效应，实际 {b}");
    }

    #[test]
    fn blockiness_smooth_image_low() {
        // 全平滑（同值）图块效应为 0
        let pixels = vec![100u8; 32 * 4];
        assert_eq!(blockiness_gray(&pixels, 32, 4), 0.0);
    }

    #[test]
    fn cooccurrence_counts_adjacent_pairs_within_block() {
        // 单块：block[0] 是 DC 不参与，统计 block[1..64] 相邻对
        let mut block = [0i16; 64];
        block[1] = 1;
        block[2] = 2; // 相邻对 (1,2)
        block[3] = 1; // 相邻对 (2,1)
        let m = cooccurrence(std::slice::from_ref(&block));
        let dim = (COOC_BOUND as usize) * 2 + 1;
        let idx = |a: i16, b: i16| -> usize {
            ((a + COOC_BOUND) as usize) * dim + (b + COOC_BOUND) as usize
        };
        assert_eq!(m[idx(1, 2)], 1);
        assert_eq!(m[idx(2, 1)], 1);
        // 共 62 个块内相邻对
        let total: usize = m.iter().sum();
        assert_eq!(total, 62);
    }

    #[test]
    fn cooc_l1_identical_is_zero() {
        let block = [[1i16; 64]];
        let m = cooccurrence(&block);
        assert_eq!(cooc_l1(&m, &m), 0.0);
    }

    #[test]
    fn score_strong_shrinkage_points_to_f5_high() {
        // 零占比大幅升高 + 高一阶/二阶散度 → High 且归因 F5（零收缩主导）
        let (score, verdict, guess) = score_report(0.08, 0.4, 0.3, 0.5);
        assert_eq!(verdict, Verdict::High);
        assert_eq!(guess, AlgorithmGuess::F5);
        assert!(score >= 75);
    }

    #[test]
    fn score_cooccurrence_dominant_points_to_steghide() {
        // 一阶零占比/直方图正常，但二阶共现散度很大 → 倾向 steghide
        let (_score, _verdict, guess) = score_report(0.0, 0.05, 0.3, 0.2);
        assert_eq!(guess, AlgorithmGuess::Steghide);
    }

    #[test]
    fn score_clean_baseline() {
        let (score, verdict, guess) = score_report(0.0, 0.0, 0.0, 0.0);
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
