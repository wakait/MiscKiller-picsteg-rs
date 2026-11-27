//! PNG/BMP 的 LSB 卡方（chi-square）统计攻击（Westfeld/Pfitzmann 经典方法）。
//!
//! LSB 顺序嵌入会把秘密比特随机写进像素最低位，使像素值配对 POC（pairs of
//! values，(0,1)(2,3)…(254,255)）内两值的频次趋于相等。本模块不依赖明文特征，
//! 仅统计 256 个像素值频次，计算卡方量与其上侧 p 值：p→1 表示 LSB 接近完全随机
//! （疑似全嵌入），p→0 表示自然图像。再沿扫描线分块累计直方图，得到 p 值随数据
//! 量上升的曲线，用于估计大致嵌入比例。
//!
//! 能力红线：仅对**顺序、LSB 位平面替换**敏感；对随机/非顺序散布、非 LSB 位、
//! 调色板索引 BMP、低比例部分嵌入（全图 p 钝化，仅曲线可提示）、F5/steghide 等
//! JPEG DCT 算法无效。输出为统计概率而非确定结论，仅供研判。
//!
//! 全部数值（含正则化不完全伽马函数）手写，仅依赖 std 的 f64 超越函数，零第三方
//! 统计 crate、零 C 依赖，三平台行为一致。

use crate::imageio::Image;

/// 单通道一次卡方检验结果。
#[derive(Debug, Clone, Copy, PartialEq)]
struct ChiStat {
    /// 卡方统计量 chi2
    chi2: f64,
    /// 自由度 df = 有效配对数 - 1
    df: usize,
}

/// 分块曲线上的一个点：处理到 `progress` 比例样本时的 p 值。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CurvePoint {
    /// 已处理样本占全通道的比例（0~1）
    pub progress: f64,
    /// 截至该点累计参与统计的像素数
    pub samples: usize,
    /// 该前缀的卡方上侧 p 值（0~1）
    pub p: f64,
}

/// 单个颜色通道的完整分析结果。
#[derive(Debug, Clone)]
pub struct ChannelReport {
    /// 通道索引：0=R, 1=G, 2=B, 3=A
    pub ch: u8,
    /// 是否有效（有效 POC 配对不足，如 alpha 恒定时为 false）
    pub usable: bool,
    /// 全图卡方量
    pub chi2: f64,
    /// 自由度
    pub df: usize,
    /// 全图 p 值
    pub p_full: f64,
    /// 分块曲线中的峰值 p：对"前段嵌入、后段为原始数据"的部分嵌入更敏感，
    /// 避免全图 p 被未嵌入区域稀释而漏报
    pub p_peak: f64,
    /// 嵌入比例估计：p 首次达到 0.95 的前缀进度，未达成为 0
    pub embed_ratio: f64,
    /// 分块 p 值曲线
    pub curve: Vec<CurvePoint>,
}

/// 整张图的卡方攻击汇总报告。
#[derive(Debug, Clone)]
pub struct ChiReport {
    /// 各通道报告（按请求顺序）
    pub channels: Vec<ChannelReport>,
    /// 综合中文结论
    pub verdict: String,
    /// 综合可疑度 0..=100（取有效通道最高 p 映射）
    pub score: u8,
}

/// p 值达到"疑似嵌入"的门限。
const P_STRONG: f64 = 0.95;
/// p 值进入"部分嵌入可疑"的门限。
const P_WEAK: f64 = 0.5;

/// Lanczos-7 系数（Numerical Recipes 经典取值），用于 ln Gamma 近似。
const LANCZOS_COEF: [f64; 6] = [
    76.18009172947146,
    -86.50532032941677,
    24.01409824083091,
    -1.231739572450155,
    0.1208650973866179e-2,
    -0.5395239384953e-5,
];

/// 伽马函数的自然对数 ln Γ(a)，Lanczos 近似，a>0。
fn ln_gamma(a: f64) -> f64 {
    let x = a;
    let mut y = a;
    let mut tmp = a + 5.5;
    tmp -= (a + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for &c in &LANCZOS_COEF {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

/// 级数展开求正则化下不完全伽马 P(a,x)，适用于 x < a+1。
fn gamma_series(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut ap = a;
    let mut sum = 1.0 / a;
    let mut term = sum;
    for _ in 0..200 {
        ap += 1.0;
        term *= x / ap;
        sum += term;
        if term.abs() < 3e-12 * sum.abs() {
            break;
        }
    }
    // 公共因子，避免大 a 时下溢
    sum * (-x + a * x.ln() - ln_gamma(a)).exp()
}

/// Lentz 连分式求正则化下不完全伽马 P(a,x) 的补，适用于 x >= a+1。
fn gamma_cf(a: f64, x: f64) -> f64 {
    let tiny = 1e-30;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / tiny;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..=200 {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < tiny {
            d = tiny;
        }
        c = b + an / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < 3e-12 {
            break;
        }
    }
    // 返回 Q(a,x)=1-P(a,x)
    (-x + a * x.ln() - ln_gamma(a)).exp() * h
}

/// 正则化下不完全伽马函数 P(a,x)，返回值 clamp 到 [0,1]。
fn gammp(a: f64, x: f64) -> f64 {
    if a <= 0.0 || x < 0.0 {
        return 0.0;
    }
    if x == 0.0 {
        return 0.0;
    }
    let p = if x < a + 1.0 {
        gamma_series(a, x)
    } else {
        1.0 - gamma_cf(a, x)
    };
    p.clamp(0.0, 1.0)
}

/// 卡方分布上侧概率 p = 1 - P(df/2, chi2/2)。
/// chi2<=0 时 LSB 完全均衡，p=1；返回值 clamp 到 [0,1]。
fn chi_pvalue(chi2: f64, df: usize) -> f64 {
    if df == 0 {
        return 0.0;
    }
    if chi2 <= 0.0 {
        return 1.0;
    }
    let a = df as f64 / 2.0;
    let x = chi2 / 2.0;
    (1.0 - gammp(a, x)).clamp(0.0, 1.0)
}

/// 统计 RGBA8 像素缓冲中指定通道的 256 个像素值频次。
/// `pixels` 为每像素 4 字节紧密排列，索引 `(y*width+x)*4 + ch`。
fn channel_histogram(pixels: &[u8], width: u32, height: u32, ch: usize) -> [usize; 256] {
    let mut hist = [0usize; 256];
    let n = (width as usize) * (height as usize);
    for i in 0..n {
        let v = pixels[i * 4 + ch];
        hist[v as usize] += 1;
    }
    hist
}

/// 对 256 桶直方图做卡方检验：128 个 POC，期望频次为对内两值均值，
/// 仅期望>0 的配对参与。有效配对少于 2 时返回 None（自由度无意义）。
fn chi_square(hist: &[usize; 256]) -> Option<ChiStat> {
    let mut chi2 = 0.0f64;
    let mut pairs = 0usize;
    for i in 0..128 {
        let h0 = hist[2 * i] as f64;
        let h1 = hist[2 * i + 1] as f64;
        let expected = (h0 + h1) / 2.0;
        if expected > 0.0 {
            chi2 += (h0 - expected).powi(2) / expected;
            pairs += 1;
        }
    }
    if pairs < 2 {
        return None;
    }
    Some(ChiStat {
        chi2,
        df: pairs - 1,
    })
}

/// 分析单个通道：全图检验 + 沿扫描线增量分块的 p 值曲线。
fn analyze_channel(
    pixels: &[u8],
    width: u32,
    height: u32,
    ch: usize,
    blocks: usize,
) -> ChannelReport {
    let total = (width as usize) * (height as usize);
    let blocks = blocks.max(1);

    // 增量直方图：逐块累加，避免重复全扫
    let mut hist = [0usize; 256];
    let mut curve = Vec::with_capacity(blocks);
    let block_size = (total / blocks).max(1);
    let mut counted = 0usize;
    let mut embed_ratio = 0.0f64;
    let mut threshold_hit = false;

    for b in 0..blocks {
        let end = if b == blocks - 1 {
            total
        } else {
            ((b + 1) * block_size).min(total)
        };
        for i in counted..end {
            hist[pixels[i * 4 + ch] as usize] += 1;
        }
        counted = end;

        if let Some(stat) = chi_square(&hist) {
            let p = chi_pvalue(stat.chi2, stat.df);
            let progress = counted as f64 / total as f64;
            curve.push(CurvePoint {
                progress,
                samples: counted,
                p,
            });
            if !threshold_hit && p >= P_STRONG {
                embed_ratio = progress;
                threshold_hit = true;
            }
        }
    }

    // 全图统计（直接用累计满的直方图，保证与曲线末点一致）
    let full_hist = channel_histogram(pixels, width, height, ch);
    // 曲线峰值：取所有分块 p 的最大值，反映是否存在持续的 LSB 均衡段
    let p_peak = curve.iter().map(|pt| pt.p).fold(0.0f64, f64::max);
    match chi_square(&full_hist) {
        Some(stat) => {
            let p_full = chi_pvalue(stat.chi2, stat.df);
            ChannelReport {
                ch: ch as u8,
                usable: true,
                chi2: stat.chi2,
                df: stat.df,
                p_full,
                p_peak,
                embed_ratio,
                curve,
            }
        }
        None => ChannelReport {
            ch: ch as u8,
            usable: false,
            chi2: 0.0,
            df: 0,
            p_full: 0.0,
            p_peak: 0.0,
            embed_ratio: 0.0,
            curve: Vec::new(),
        },
    }
}

/// 由全图 p 与曲线峰值映射中文结论与 0..=100 可疑度。
/// 取两者较大值：全图 p 捕捉全嵌入，峰值 p 捕捉前段嵌入后段原始的部分嵌入。
fn classify(p_full: f64, p_peak: f64) -> (String, u8) {
    let p = p_full.max(p_peak);
    if p >= P_STRONG {
        (
            "疑似 LSB 嵌入".to_string(),
            (p * 100.0).round().clamp(0.0, 100.0) as u8,
        )
    } else if p >= P_WEAK {
        (
            "部分嵌入可疑".to_string(),
            (p * 100.0).round().clamp(0.0, 100.0) as u8,
        )
    } else {
        (
            "未见显著 LSB 均衡".to_string(),
            (p * 100.0).round().clamp(0.0, 100.0) as u8,
        )
    }
}

/// 卡方攻击入口：对指定通道（默认 R/G/B/A 四通道）逐一分析并汇总。
pub fn analyze_image(img: &Image, channels: &[u8], blocks: usize) -> ChiReport {
    let mut reports = Vec::with_capacity(channels.len());
    for &ch in channels {
        reports.push(analyze_channel(
            &img.pixels,
            img.width,
            img.height,
            ch as usize,
            blocks,
        ));
    }

    // 综合取有效通道中 max(全图 p, 曲线峰值 p) 的最强证据，
    // 兼顾全嵌入与前段部分嵌入（后者全图 p 会被未嵌入区域稀释）
    let best_p = reports
        .iter()
        .filter(|r| r.usable)
        .map(|r| r.p_full.max(r.p_peak))
        .fold(0.0f64, f64::max);
    let (verdict, score) = classify(0.0, best_p);

    ChiReport {
        channels: reports,
        verdict,
        score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln_gamma_known_values() {
        // Γ(1)=1 → ln=0；Γ(2)=1 → ln=0；Γ(0.5)=sqrt(pi) → ln=0.5ln(pi)
        assert!((ln_gamma(1.0) - 0.0).abs() < 1e-10);
        assert!((ln_gamma(2.0) - 0.0).abs() < 1e-10);
        assert!((ln_gamma(0.5) - (std::f64::consts::PI.ln() / 2.0)).abs() < 1e-9);
        // Γ(5)=24 → ln24
        assert!((ln_gamma(5.0) - 24.0f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn gammp_boundaries() {
        assert_eq!(gammp(1.0, 0.0), 0.0);
        // P(a,x) 单调且在大 x 时趋近 1
        assert!(gammp(2.0, 50.0) > 0.9999);
        // 非法 a 防护
        assert_eq!(gammp(0.0, 1.0), 0.0);
    }

    #[test]
    fn chi_pvalue_matches_critical_values() {
        // 常用卡方临界值：p≈0.05 的对照（容差 1e-3，数值核为近似实现）
        let p1 = chi_pvalue(3.841, 1);
        let p2 = chi_pvalue(5.991, 2);
        let p10 = chi_pvalue(18.307, 10);
        assert!((p1 - 0.05).abs() < 1e-3, "df=1 got {p1}");
        assert!((p2 - 0.05).abs() < 1e-3, "df=2 got {p2}");
        assert!((p10 - 0.05).abs() < 1e-3, "df=10 got {p10}");
    }

    #[test]
    fn chi_pvalue_extremes() {
        // chi2=0 → LSB 完全均衡 → p=1
        assert!((chi_pvalue(0.0, 5) - 1.0).abs() < 1e-12);
        // 极大 chi2 → p→0
        assert!(chi_pvalue(1000.0, 4) < 1e-9);
        // df=0 防护
        assert_eq!(chi_pvalue(1.0, 0), 0.0);
    }

    #[test]
    fn perfectly_balanced_pairs_give_p_one() {
        // 每个 POC 内两值频次严格相等 → chi2=0 → p=1
        let hist = [100usize; 256]; // 所有值等频，任意对内都均衡
        let stat = chi_square(&hist).expect("应有效");
        assert!(stat.chi2.abs() < 1e-9);
        assert_eq!(stat.df, 127);
        assert!((chi_pvalue(stat.chi2, stat.df) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn only_even_values_give_low_p() {
        // 只填偶数值，奇数值恒为 0 → 对内严重失衡 → 大 chi2、低 p
        let mut hist = [0usize; 256];
        for i in (0..256).step_by(2) {
            hist[i] = 200;
        }
        let stat = chi_square(&hist).expect("应有效");
        assert!(stat.chi2 > 1000.0);
        assert!(chi_pvalue(stat.chi2, stat.df) < 1e-6);
    }

    #[test]
    fn degenerate_histogram_is_none() {
        // 只有一个非零值 → 有效配对不足 2 → None
        let mut hist = [0usize; 256];
        hist[0] = 1000;
        assert!(chi_square(&hist).is_none());
    }

    #[test]
    fn channel_histogram_counts_rgba() {
        // 2x1 RGBA8：两个像素，R 通道分别为 10、10
        let pixels = vec![
            10, 20, 30, 255, // px0
            10, 40, 50, 255, // px1
        ];
        let hist = channel_histogram(&pixels, 2, 1, 0);
        assert_eq!(hist[10], 2);
        assert_eq!(hist.iter().sum::<usize>(), 2);
        let g = channel_histogram(&pixels, 2, 1, 1);
        assert_eq!(g[20], 1);
        assert_eq!(g[40], 1);
    }

    #[test]
    fn constant_alpha_channel_marked_unusable() {
        // alpha 全部 255 → 单值直方图 → 该通道标记不可用
        let w = 4u32;
        let h = 2u32;
        let mut pixels = vec![0u8; (w * h * 4) as usize];
        for px in pixels.as_chunks_mut::<4>().0 {
            px[3] = 255;
            // RGB 给些变化，保证 RGB 通道本身有效
            px[0] = (px[0].wrapping_add(1)).wrapping_mul(7);
        }
        let alpha = analyze_channel(&pixels, w, h, 3, 4);
        assert!(!alpha.usable, "恒定 alpha 应标记不可用");
        assert!(alpha.curve.is_empty());
    }

    #[test]
    fn balanced_image_full_p_is_high() {
        // 构造 LSB 已均衡的 RGBA 图：在多个 POC 对内让两值等量出现
        let w = 8u32;
        let h = 8u32;
        let n = (w * h) as usize;
        let mut pixels = vec![0u8; n * 4];
        // 像素循环取 0/1、2/3、4/5、6/7，形成 4 个有效 POC 且对内等量
        let palette = [0u8, 1, 2, 3, 4, 5, 6, 7];
        for i in 0..n {
            let v = palette[i % palette.len()];
            let px = &mut pixels[i * 4..i * 4 + 4];
            px[0] = v;
            px[1] = v;
            px[2] = v;
            px[3] = 255;
        }
        let report = analyze_channel(&pixels, w, h, 0, 4);
        assert!(report.usable);
        assert!(
            report.p_full > 0.9,
            "均衡图 p 应接近 1，实际 {}",
            report.p_full
        );
    }

    #[test]
    fn analyze_image_aggregates_best_p() {
        // 一张小图，四通道全分析；汇总 score 等于最高有效 p 的百分制
        let w = 4u32;
        let h = 4u32;
        let n = (w * h) as usize;
        let mut pixels = vec![0u8; n * 4];
        let palette = [0u8, 1, 2, 3, 4, 5, 6, 7];
        for i in 0..n {
            let v = palette[i % palette.len()];
            let px = &mut pixels[i * 4..i * 4 + 4];
            px[0] = v;
            px[1] = v;
            px[2] = v;
            px[3] = 255; // alpha 退化
        }
        let img = Image {
            format: crate::imageio::ImgFormat::Png,
            width: w,
            height: h,
            pixels,
            imagedata: Vec::new(),
            metadata: std::collections::HashMap::new(),
            chunks: Vec::new(),
            extradata: Vec::new(),
        };
        let report = analyze_image(&img, &[0, 1, 2, 3], 4);
        assert_eq!(report.channels.len(), 4);
        // 三个 RGB 通道有效，alpha 不可用
        assert!(!report.channels[3].usable, "恒定 alpha 应标记不可用");
        assert!(report.channels[0].usable);
        assert!(report.score >= 90, "强均衡图应高分，实际 {}", report.score);
    }
}
