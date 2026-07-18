// trend_analyzer.cpp
// Batch 12: Trend Analysis Engine
//
// Analyzes performance trends over time
// Features: Linear regression, moving averages, trend detection

#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <optional>

namespace Benchmark {
namespace Analytics {

// Data point for time series
struct TimeSeriesPoint {
    double timestamp;  // Unix timestamp or sequential index
    double value;
    std::optional<double> weight;  // For weighted regression
};

// Trend analysis result
struct TrendResult {
    double slope;                    // Rate of change
    double intercept;                // Y-intercept
    double r_squared;              // Coefficient of determination (0-1)
    double correlation;              // Pearson correlation coefficient
    double p_value;                // Statistical significance
    bool is_significant;             // p < 0.05
    std::string direction;           // "improving", "degrading", "stable"
    double confidence_lower;         // 95% CI lower bound
    double confidence_upper;         // 95% CI upper bound
};

// Linear regression calculator
class LinearRegression {
public:
    static TrendResult Calculate(const std::vector<TimeSeriesPoint>& data) {
        TrendResult result = {};
        
        if (data.size() < 2) {
            return result;
        }
        
        size_t n = data.size();
        
        // Calculate means
        double sum_x = 0.0, sum_y = 0.0;
        double sum_weights = 0.0;
        
        for (const auto& point : data) {
            double w = point.weight.value_or(1.0);
            sum_x += point.timestamp * w;
            sum_y += point.value * w;
            sum_weights += w;
        }
        
        double mean_x = sum_x / sum_weights;
        double mean_y = sum_y / sum_weights;
        
        // Calculate slope and intercept
        double numerator = 0.0;
        double denominator = 0.0;
        double ss_res = 0.0;
        double ss_tot = 0.0;
        
        for (const auto& point : data) {
            double w = point.weight.value_or(1.0);
            double x_diff = point.timestamp - mean_x;
            double y_diff = point.value - mean_y;
            
            numerator += w * x_diff * y_diff;
            denominator += w * x_diff * x_diff;
            ss_tot += w * y_diff * y_diff;
        }
        
        if (denominator == 0.0) {
            return result;  // No variation in x
        }
        
        result.slope = numerator / denominator;
        result.intercept = mean_y - result.slope * mean_x;
        
        // Calculate R-squared
        for (const auto& point : data) {
            double predicted = result.intercept + result.slope * point.timestamp;
            double residual = point.value - predicted;
            double w = point.weight.value_or(1.0);
            ss_res += w * residual * residual;
        }
        
        result.r_squared = (ss_tot > 0.0) ? 1.0 - (ss_res / ss_tot) : 0.0;
        
        // Calculate correlation
        result.correlation = std::sqrt(result.r_squared);
        if (result.slope < 0) {
            result.correlation = -result.correlation;
        }
        
        // Calculate standard error and confidence intervals
        double se = std::sqrt(ss_res / (n - 2));
        double sxx = 0.0;
        for (const auto& point : data) {
            double w = point.weight.value_or(1.0);
            sxx += w * (point.timestamp - mean_x) * (point.timestamp - mean_x);
        }
        
        double se_slope = se / std::sqrt(sxx);
        double t_value = 1.96;  // Approximate for 95% CI with large n
        
        result.confidence_lower = result.slope - t_value * se_slope;
        result.confidence_upper = result.slope + t_value * se_slope;
        
        // Determine direction
        if (std::abs(result.slope) < 0.01) {
            result.direction = "stable";
        } else if (result.slope > 0) {
            result.direction = "improving";
        } else {
            result.direction = "degrading";
        }
        
        // Statistical significance (simplified)
        result.p_value = CalculatePValue(result.correlation, n);
        result.is_significant = result.p_value < 0.05;
        
        return result;
    }
    
    // Predict future value
    static double Predict(const TrendResult& trend, double timestamp) {
        return trend.intercept + trend.slope * timestamp;
    }
    
    // Calculate prediction interval
    static std::pair<double, double> PredictionInterval(
        const TrendResult& trend,
        const std::vector<TimeSeriesPoint>& data,
        double timestamp,
        double confidence = 0.95) {
        
        if (data.size() < 3) {
            return {0.0, 0.0};
        }
        
        double predicted = Predict(trend, timestamp);
        
        // Calculate standard error of prediction
        double mean_x = 0.0;
        for (const auto& point : data) {
            mean_x += point.timestamp;
        }
        mean_x /= data.size();
        
        double sxx = 0.0;
        double sse = 0.0;
        for (const auto& point : data) {
            double pred = trend.intercept + trend.slope * point.timestamp;
            sse += (point.value - pred) * (point.value - pred);
            sxx += (point.timestamp - mean_x) * (point.timestamp - mean_x);
        }
        
        double mse = sse / (data.size() - 2);
        double se = std::sqrt(mse * (1.0 + 1.0/data.size() + 
            (timestamp - mean_x) * (timestamp - mean_x) / sxx));
        
        double t_value = 1.96;  // 95% CI
        double margin = t_value * se;
        
        return {predicted - margin, predicted + margin};
    }

private:
    static double CalculatePValue(double correlation, size_t n) {
        // Simplified p-value calculation
        if (n < 3) return 1.0;
        
        double t_stat = correlation * std::sqrt((n - 2) / (1 - correlation * correlation));
        // For large n, approximate using normal distribution
        return std::exp(-0.5 * t_stat * t_stat) / std::sqrt(2 * M_PI);
    }
};

// Moving average calculator
class MovingAverage {
public:
    enum class Type {
        SIMPLE,      // SMA
        EXPONENTIAL, // EMA
        WEIGHTED     // WMA
    };
    
    static std::vector<double> Calculate(
        const std::vector<double>& data,
        size_t window,
        Type type = Type::SIMPLE) {
        
        if (window == 0 || data.size() < window) {
            return data;
        }
        
        std::vector<double> result;
        result.reserve(data.size());
        
        switch (type) {
            case Type::SIMPLE:
                result = CalculateSMA(data, window);
                break;
            case Type::EXPONENTIAL:
                result = CalculateEMA(data, window);
                break;
            case Type::WEIGHTED:
                result = CalculateWMA(data, window);
                break;
        }
        
        return result;
    }
    
    // Calculate trend strength using moving average convergence
    static double CalculateTrendStrength(
        const std::vector<double>& data,
        size_t short_window = 10,
        size_t long_window = 30) {
        
        if (data.size() < long_window) {
            return 0.0;
        }
        
        auto short_ma = CalculateSMA(data, short_window);
        auto long_ma = CalculateSMA(data, long_window);
        
        // Compare last values
        double short_val = short_ma.back();
        double long_val = long_ma.back();
        
        if (long_val == 0.0) return 0.0;
        
        return (short_val - long_val) / long_val;
    }

private:
    static std::vector<double> CalculateSMA(
        const std::vector<double>& data, size_t window) {
        std::vector<double> result;
        result.reserve(data.size());
        
        double sum = 0.0;
        for (size_t i = 0; i < data.size(); ++i) {
            sum += data[i];
            
            if (i >= window) {
                sum -= data[i - window];
            }
            
            if (i >= window - 1) {
                result.push_back(sum / window);
            } else {
                result.push_back(sum / (i + 1));  // Cumulative average
            }
        }
        
        return result;
    }
    
    static std::vector<double> CalculateEMA(
        const std::vector<double>& data, size_t window) {
        std::vector<double> result;
        result.reserve(data.size());
        
        double multiplier = 2.0 / (window + 1);
        double ema = data[0];
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (i == 0) {
                ema = data[i];
            } else {
                ema = (data[i] - ema) * multiplier + ema;
            }
            result.push_back(ema);
        }
        
        return result;
    }
    
    static std::vector<double> CalculateWMA(
        const std::vector<double>& data, size_t window) {
        std::vector<double> result;
        result.reserve(data.size());
        
        for (size_t i = 0; i < data.size(); ++i) {
            size_t start = (i >= window - 1) ? i - window + 1 : 0;
            size_t count = i - start + 1;
            
            double weighted_sum = 0.0;
            double weight_sum = 0.0;
            
            for (size_t j = start; j <= i; ++j) {
                double weight = j - start + 1;
                weighted_sum += data[j] * weight;
                weight_sum += weight;
            }
            
            result.push_back(weighted_sum / weight_sum);
        }
        
        return result;
    }
};

// Seasonality detector
class SeasonalityDetector {
public:
    struct SeasonalityResult {
        bool has_seasonality;
        int period;                      // Detected period
        double strength;                 // 0-1, strength of seasonal component
        std::vector<double> seasonal_component;
        std::vector<double> trend_component;
        std::vector<double> residual_component;
    };
    
    // Detect seasonality using autocorrelation
    static SeasonalityResult Detect(
        const std::vector<double>& data,
        int max_period = 100) {
        
        SeasonalityResult result = {};
        
        if (data.size() < 4) {
            result.has_seasonality = false;
            return result;
        }
        
        // Calculate autocorrelation
        std::vector<double> autocorr = CalculateAutocorrelation(data, max_period);
        
        // Find peak in autocorrelation (excluding lag 0)
        double max_corr = 0.0;
        int best_period = 0;
        
        for (int lag = 1; lag < static_cast<int>(autocorr.size()); ++lag) {
            if (autocorr[lag] > max_corr) {
                max_corr = autocorr[lag];
                best_period = lag;
            }
        }
        
        // Threshold for seasonality detection
        result.has_seasonality = max_corr > 0.3;
        result.period = best_period;
        result.strength = max_corr;
        
        if (result.has_seasonality && best_period > 0) {
            Decompose(data, best_period, result);
        }
        
        return result;
    }

private:
    static std::vector<double> CalculateAutocorrelation(
        const std::vector<double>& data, int max_lag) {
        
        std::vector<double> result;
        result.reserve(max_lag + 1);
        
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        
        // Calculate variance
        double variance = 0.0;
        for (double x : data) {
            variance += (x - mean) * (x - mean);
        }
        variance /= data.size();
        
        if (variance == 0.0) {
            return std::vector<double>(max_lag + 1, 0.0);
        }
        
        // Calculate autocorrelation for each lag
        for (int lag = 0; lag <= max_lag && lag < static_cast<int>(data.size()); ++lag) {
            double autocov = 0.0;
            for (size_t i = lag; i < data.size(); ++i) {
                autocov += (data[i] - mean) * (data[i - lag] - mean);
            }
            autocov /= data.size();
            result.push_back(autocov / variance);
        }
        
        return result;
    }
    
    static void Decompose(const std::vector<double>& data, int period,
                         SeasonalityResult& result) {
        
        // Simple seasonal decomposition
        result.trend_component = MovingAverage::Calculate(data, period);
        
        // Calculate seasonal component
        result.seasonal_component.resize(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            result.seasonal_component[i] = data[i] - result.trend_component[i];
        }
        
        // Residual
        result.residual_component.resize(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            result.residual_component[i] = data[i] - result.trend_component[i] 
                                          - result.seasonal_component[i];
        }
    }
};

// Change point detection
class ChangePointDetector {
public:
    struct ChangePoint {
        size_t index;
        double confidence;
        double before_mean;
        double after_mean;
    };
    
    // Detect change points using CUSUM
    static std::vector<ChangePoint> DetectCUSUM(
        const std::vector<double>& data,
        double threshold = 5.0,
        double drift = 0.0) {
        
        std::vector<ChangePoint> change_points;
        
        if (data.size() < 2) return change_points;
        
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        double s_pos = 0.0, s_neg = 0.0;
        
        for (size_t i = 0; i < data.size(); ++i) {
            s_pos = std::max(0.0, s_pos + data[i] - mean - drift);
            s_neg = std::min(0.0, s_neg + data[i] - mean + drift);
            
            if (s_pos > threshold || std::abs(s_neg) > threshold) {
                ChangePoint cp;
                cp.index = i;
                cp.confidence = std::min(s_pos, std::abs(s_neg)) / threshold;
                
                // Calculate before/after means
                if (i > 0) {
                    cp.before_mean = std::accumulate(data.begin(), data.begin() + i, 0.0) / i;
                }
                if (i < data.size() - 1) {
                    cp.after_mean = std::accumulate(data.begin() + i + 1, data.end(), 0.0) 
                                   / (data.size() - i - 1);
                }
                
                change_points.push_back(cp);
                s_pos = 0.0;
                s_neg = 0.0;
            }
        }
        
        return change_points;
    }
};

} // namespace Analytics
} // namespace Benchmark
