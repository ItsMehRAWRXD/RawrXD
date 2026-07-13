// statistical_analysis.cpp
// Batch 12: Advanced Statistical Analysis Tools
//
// Provides comprehensive statistical analysis capabilities
// Features: Hypothesis testing, correlation analysis, distribution fitting

#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <map>
#include <functional>

namespace Benchmark {
namespace Analytics {

// Descriptive statistics
struct DescriptiveStats {
    size_t n;
    double mean;
    double median;
    double std_dev;
    double variance;
    double min;
    double max;
    double range;
    double skewness;
    double kurtosis;
    double cv;  // Coefficient of variation
    
    // Percentiles
    double p5;
    double p10;
    double p25;
    double p75;
    double p90;
    double p95;
    double p99;
    
    // Confidence intervals
    double ci95_lower;
    double ci95_upper;
    
    static DescriptiveStats Calculate(const std::vector<double>& data) {
        DescriptiveStats stats = {};
        
        if (data.empty()) return stats;
        
        stats.n = data.size();
        
        // Basic statistics
        stats.min = *std::min_element(data.begin(), data.end());
        stats.max = *std::max_element(data.begin(), data.end());
        stats.range = stats.max - stats.min;
        
        stats.mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        
        // Variance and standard deviation
        double sum_squared_diff = 0.0;
        double sum_cubed_diff = 0.0;
        double sum_fourth_diff = 0.0;
        
        for (double x : data) {
            double diff = x - stats.mean;
            sum_squared_diff += diff * diff;
            sum_cubed_diff += diff * diff * diff;
            sum_fourth_diff += diff * diff * diff * diff;
        }
        
        stats.variance = sum_squared_diff / data.size();
        stats.std_dev = std::sqrt(stats.variance);
        stats.cv = (stats.mean != 0.0) ? stats.std_dev / stats.mean : 0.0;
        
        // Skewness and kurtosis
        if (stats.std_dev > 0.0 && data.size() > 2) {
            stats.skewness = (sum_cubed_diff / data.size()) / 
                            (stats.std_dev * stats.std_dev * stats.std_dev);
            stats.kurtosis = (sum_fourth_diff / data.size()) / 
                            (stats.variance * stats.variance) - 3.0;
        }
        
        // Median and percentiles
        std::vector<double> sorted = data;
        std::sort(sorted.begin(), sorted.end());
        
        stats.median = Percentile(sorted, 0.5);
        stats.p5 = Percentile(sorted, 0.05);
        stats.p10 = Percentile(sorted, 0.10);
        stats.p25 = Percentile(sorted, 0.25);
        stats.p75 = Percentile(sorted, 0.75);
        stats.p90 = Percentile(sorted, 0.90);
        stats.p95 = Percentile(sorted, 0.95);
        stats.p99 = Percentile(sorted, 0.99);
        
        // Confidence interval (95%)
        double se = stats.std_dev / std::sqrt(data.size());
        double t_value = 1.96;  // Approximate for large n
        stats.ci95_lower = stats.mean - t_value * se;
        stats.ci95_upper = stats.mean + t_value * se;
        
        return stats;
    }
    
private:
    static double Percentile(const std::vector<double>& sorted, double p) {
        if (sorted.empty()) return 0.0;
        
        double pos = p * (sorted.size() - 1);
        size_t idx = static_cast<size_t>(pos);
        double frac = pos - idx;
        
        if (idx + 1 < sorted.size()) {
            return sorted[idx] * (1.0 - frac) + sorted[idx + 1] * frac;
        }
        return sorted[idx];
    }
};

// Hypothesis testing
class HypothesisTests {
public:
    // T-test for comparing means
    struct TTestResult {
        double t_statistic;
        double p_value;
        double df;  // Degrees of freedom
        bool significant;  // p < 0.05
        double mean_diff;
        double ci_lower;
        double ci_upper;
    };
    
    static TTestResult TTestIndependent(
        const std::vector<double>& sample1,
        const std::vector<double>& sample2) {
        
        TTestResult result = {};
        
        if (sample1.size() < 2 || sample2.size() < 2) {
            return result;
        }
        
        // Calculate means
        double mean1 = std::accumulate(sample1.begin(), sample1.end(), 0.0) / sample1.size();
        double mean2 = std::accumulate(sample2.begin(), sample2.end(), 0.0) / sample2.size();
        result.mean_diff = mean1 - mean2;
        
        // Calculate variances
        double var1 = 0.0, var2 = 0.0;
        for (double x : sample1) {
            var1 += (x - mean1) * (x - mean1);
        }
        var1 /= (sample1.size() - 1);
        
        for (double x : sample2) {
            var2 += (x - mean2) * (x - mean2);
        }
        var2 /= (sample2.size() - 1);
        
        // Pooled standard error
        double se = std::sqrt(var1 / sample1.size() + var2 / sample2.size());
        
        // Welch's t-test (doesn't assume equal variances)
        result.t_statistic = result.mean_diff / se;
        
        // Degrees of freedom (Welch-Satterthwaite)
        double num = (var1 / sample1.size() + var2 / sample2.size()) * 
                     (var1 / sample1.size() + var2 / sample2.size());
        double den = (var1 * var1) / (sample1.size() * sample1.size() * (sample1.size() - 1)) +
                     (var2 * var2) / (sample2.size() * sample2.size() * (sample2.size() - 1));
        result.df = num / den;
        
        // P-value (simplified - using normal approximation)
        result.p_value = 2.0 * (1.0 - NormalCDF(std::abs(result.t_statistic)));
        result.significant = result.p_value < 0.05;
        
        // Confidence interval
        double t_crit = 1.96;  // Approximate
        result.ci_lower = result.mean_diff - t_crit * se;
        result.ci_upper = result.mean_diff + t_crit * se;
        
        return result;
    }
    
    // Paired t-test
    static TTestResult TTestPaired(
        const std::vector<double>& before,
        const std::vector<double>& after) {
        
        if (before.size() != after.size() || before.size() < 2) {
            return {};
        }
        
        // Calculate differences
        std::vector<double> diff;
        diff.reserve(before.size());
        for (size_t i = 0; i < before.size(); ++i) {
            diff.push_back(after[i] - before[i]);
        }
        
        // T-test on differences
        return TTestIndependent(diff, std::vector<double>(diff.size(), 0.0));
    }
    
    // Mann-Whitney U test (non-parametric)
    struct MannWhitneyResult {
        double u_statistic;
        double z_score;
        double p_value;
        bool significant;
    };
    
    static MannWhitneyResult MannWhitneyUTest(
        const std::vector<double>& sample1,
        const std::vector<double>& sample2) {
        
        MannWhitneyResult result = {};
        
        // Combine and rank
        std::vector<std::pair<double, int>> combined;
        for (double x : sample1) {
            combined.push_back({x, 0});
        }
        for (double x : sample2) {
            combined.push_back({x, 1});
        }
        
        std::sort(combined.begin(), combined.end());
        
        // Calculate ranks
        double rank_sum1 = 0.0;
        for (size_t i = 0; i < combined.size(); ++i) {
            if (combined[i].second == 0) {
                rank_sum1 += i + 1;
            }
        }
        
        // U statistic
        double n1 = sample1.size();
        double n2 = sample2.size();
        result.u_statistic = rank_sum1 - n1 * (n1 + 1) / 2.0;
        
        // Normal approximation
        double mean_u = n1 * n2 / 2.0;
        double std_u = std::sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0);
        
        if (std_u > 0) {
            result.z_score = (result.u_statistic - mean_u) / std_u;
            result.p_value = 2.0 * (1.0 - NormalCDF(std::abs(result.z_score)));
            result.significant = result.p_value < 0.05;
        }
        
        return result;
    }

private:
    static double NormalCDF(double x) {
        // Approximation of standard normal CDF
        return 0.5 * (1.0 + std::erf(x / std::sqrt(2.0)));
    }
};

// Correlation analysis
class CorrelationAnalysis {
public:
    // Pearson correlation
    static double Pearson(const std::vector<double>& x,
                          const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) {
            return 0.0;
        }
        
        double mean_x = std::accumulate(x.begin(), x.end(), 0.0) / x.size();
        double mean_y = std::accumulate(y.begin(), y.end(), 0.0) / y.size();
        
        double numerator = 0.0;
        double denom_x = 0.0;
        double denom_y = 0.0;
        
        for (size_t i = 0; i < x.size(); ++i) {
            double diff_x = x[i] - mean_x;
            double diff_y = y[i] - mean_y;
            numerator += diff_x * diff_y;
            denom_x += diff_x * diff_x;
            denom_y += diff_y * diff_y;
        }
        
        if (denom_x == 0.0 || denom_y == 0.0) {
            return 0.0;
        }
        
        return numerator / std::sqrt(denom_x * denom_y);
    }
    
    // Spearman rank correlation
    static double Spearman(const std::vector<double>& x,
                           const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) {
            return 0.0;
        }
        
        // Convert to ranks
        std::vector<double> rank_x = Rank(x);
        std::vector<double> rank_y = Rank(y);
        
        return Pearson(rank_x, rank_y);
    }
    
    // Kendall's tau
    static double KendallTau(const std::vector<double>& x,
                             const std::vector<double>& y) {
        if (x.size() != y.size() || x.size() < 2) {
            return 0.0;
        }
        
        size_t concordant = 0;
        size_t discordant = 0;
        
        for (size_t i = 0; i < x.size(); ++i) {
            for (size_t j = i + 1; j < x.size(); ++j) {
                double dx = x[i] - x[j];
                double dy = y[i] - y[j];
                
                if (dx * dy > 0) {
                    ++concordant;
                } else if (dx * dy < 0) {
                    ++discordant;
                }
            }
        }
        
        size_t n = x.size();
        size_t total_pairs = n * (n - 1) / 2;
        
        return static_cast<double>(concordant - discordant) / total_pairs;
    }
    
    // Correlation matrix
    static std::vector<std::vector<double>> CorrelationMatrix(
        const std::vector<std::vector<double>>& variables) {
        
        size_t n = variables.size();
        std::vector<std::vector<double>> matrix(n, std::vector<double>(n, 1.0));
        
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                double corr = Pearson(variables[i], variables[j]);
                matrix[i][j] = corr;
                matrix[j][i] = corr;
            }
        }
        
        return matrix;
    }

private:
    static std::vector<double> Rank(const std::vector<double>& data) {
        std::vector<std::pair<double, size_t>> indexed;
        for (size_t i = 0; i < data.size(); ++i) {
            indexed.push_back({data[i], i});
        }
        
        std::sort(indexed.begin(), indexed.end());
        
        std::vector<double> ranks(data.size());
        for (size_t i = 0; i < indexed.size(); ++i) {
            ranks[indexed[i].second] = i + 1;
        }
        
        return ranks;
    }
};

// Distribution fitting
class DistributionFitting {
public:
    struct DistributionFit {
        std::string name;
        double log_likelihood;
        double aic;
        double bic;
        std::vector<double> parameters;
        double ks_statistic;  // Kolmogorov-Smirnov test
        double ks_p_value;
    };
    
    // Fit normal distribution
    static DistributionFit FitNormal(const std::vector<double>& data) {
        DistributionFit fit;
        fit.name = "Normal";
        
        if (data.empty()) return fit;
        
        // MLE estimates
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        
        double variance = 0.0;
        for (double x : data) {
            variance += (x - mean) * (x - mean);
        }
        variance /= data.size();
        double std_dev = std::sqrt(variance);
        
        fit.parameters = {mean, std_dev};
        
        // Calculate log-likelihood
        fit.log_likelihood = 0.0;
        for (double x : data) {
            fit.log_likelihood += -0.5 * std::log(2 * M_PI * variance) -
                                  (x - mean) * (x - mean) / (2 * variance);
        }
        
        fit.aic = -2 * fit.log_likelihood + 2 * 2;  // 2 parameters
        fit.bic = -2 * fit.log_likelihood + 2 * std::log(data.size());
        
        return fit;
    }
    
    // Fit exponential distribution
    static DistributionFit FitExponential(const std::vector<double>& data) {
        DistributionFit fit;
        fit.name = "Exponential";
        
        if (data.empty()) return fit;
        
        // MLE for lambda
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        double lambda = 1.0 / mean;
        
        fit.parameters = {lambda};
        
        // Log-likelihood
        fit.log_likelihood = 0.0;
        for (double x : data) {
            if (x > 0) {
                fit.log_likelihood += std::log(lambda) - lambda * x;
            }
        }
        
        fit.aic = -2 * fit.log_likelihood + 2 * 1;
        fit.bic = -2 * fit.log_likelihood + std::log(data.size());
        
        return fit;
    }
    
    // Compare distributions and select best
    static DistributionFit SelectBest(const std::vector<double>& data) {
        std::vector<DistributionFit> fits;
        
        fits.push_back(FitNormal(data));
        fits.push_back(FitExponential(data));
        
        // Select by lowest AIC
        size_t best_idx = 0;
        double best_aic = fits[0].aic;
        for (size_t i = 1; i < fits.size(); ++i) {
            if (fits[i].aic < best_aic) {
                best_aic = fits[i].aic;
                best_idx = i;
            }
        }
        
        return fits[best_idx];
    }
};

// Effect size calculations
class EffectSize {
public:
    // Cohen's d
    static double CohensD(const std::vector<double>& group1,
                          const std::vector<double>& group2) {
        if (group1.size() < 2 || group2.size() < 2) {
            return 0.0;
        }
        
        double mean1 = std::accumulate(group1.begin(), group1.end(), 0.0) / group1.size();
        double mean2 = std::accumulate(group2.begin(), group2.end(), 0.0) / group2.size();
        
        double var1 = 0.0, var2 = 0.0;
        for (double x : group1) var1 += (x - mean1) * (x - mean1);
        for (double x : group2) var2 += (x - mean2) * (x - mean2);
        
        var1 /= (group1.size() - 1);
        var2 /= (group2.size() - 1);
        
        // Pooled standard deviation
        double pooled_sd = std::sqrt(((group1.size() - 1) * var1 + 
                                       (group2.size() - 1) * var2) /
                                      (group1.size() + group2.size() - 2));
        
        if (pooled_sd == 0.0) return 0.0;
        
        return (mean1 - mean2) / pooled_sd;
    }
    
    // Interpret effect size
    static std::string InterpretCohensD(double d) {
        double abs_d = std::abs(d);
        if (abs_d < 0.2) return "negligible";
        if (abs_d < 0.5) return "small";
        if (abs_d < 0.8) return "medium";
        return "large";
    }
};

} // namespace Analytics
} // namespace Benchmark
