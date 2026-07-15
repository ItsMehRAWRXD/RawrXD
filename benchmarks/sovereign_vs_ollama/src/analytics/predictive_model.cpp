// predictive_model.cpp
// Batch 12: Predictive Modeling for Performance Forecasting
//
// Forecasts future performance based on historical data
// Features: Time series forecasting, confidence intervals, drift detection

#include <vector>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <optional>
#include <queue>

namespace Benchmark {
namespace Analytics {

// Forecast result
struct ForecastResult {
    std::vector<double> predictions;
    std::vector<double> lower_bound;
    std::vector<double> upper_bound;
    double confidence_level;
    std::string model_type;
    double rmse;              // Root mean square error on training data
    double mape;              // Mean absolute percentage error
};

// Simple Exponential Smoothing
class ExponentialSmoothing {
public:
    struct Config {
        double alpha = 0.3;           // Smoothing factor (0-1)
        double trend_alpha = 0.1;     // Trend smoothing (Holt's method)
        double seasonal_alpha = 0.1;  // Seasonal smoothing (Holt-Winters)
        int seasonal_period = 0;      // 0 = no seasonality
    };
    
    static ForecastResult Forecast(
        const std::vector<double>& data,
        int horizon,
        const Config& config = Config()) {
        
        ForecastResult result;
        result.model_type = config.seasonal_period > 0 ? 
            "Holt-Winters" : (config.trend_alpha > 0 ? "Holt" : "SES");
        result.confidence_level = 0.95;
        
        if (data.size() < 2) {
            return result;
        }
        
        // Initialize
        double level = data[0];
        double trend = 0.0;
        std::vector<double> seasonal;
        
        if (config.seasonal_period > 0) {
            seasonal.resize(config.seasonal_period, 0.0);
            // Initialize seasonal components
            for (int i = 0; i < config.seasonal_period && i < static_cast<int>(data.size()); ++i) {
                seasonal[i] = data[i] - level;
            }
        }
        
        // Fit model
        std::vector<double> fitted;
        fitted.reserve(data.size());
        
        for (size_t t = 0; t < data.size(); ++t) {
            double seasonal_component = 0.0;
            if (config.seasonal_period > 0) {
                seasonal_component = seasonal[t % config.seasonal_period];
            }
            
            double forecast = level + trend + seasonal_component;
            fitted.push_back(forecast);
            
            double observation = data[t];
            double prev_level = level;
            
            // Update level
            level = config.alpha * (observation - seasonal_component) + 
                    (1 - config.alpha) * (level + trend);
            
            // Update trend
            if (config.trend_alpha > 0) {
                trend = config.trend_alpha * (level - prev_level) + 
                        (1 - config.trend_alpha) * trend;
            }
            
            // Update seasonal
            if (config.seasonal_period > 0) {
                int idx = t % config.seasonal_period;
                seasonal[idx] = config.seasonal_alpha * (observation - level) + 
                                (1 - config.seasonal_alpha) * seasonal_component;
            }
        }
        
        // Calculate errors
        result.rmse = CalculateRMSE(data, fitted);
        result.mape = CalculateMAPE(data, fitted);
        
        // Generate forecasts
        result.predictions.reserve(horizon);
        result.lower_bound.reserve(horizon);
        result.upper_bound.reserve(horizon);
        
        double forecast_level = level;
        double forecast_trend = trend;
        
        for (int h = 1; h <= horizon; ++h) {
            double seasonal_component = 0.0;
            if (config.seasonal_period > 0) {
                int idx = (data.size() + h - 1) % config.seasonal_period;
                seasonal_component = seasonal[idx];
            }
            
            double prediction = forecast_level + h * forecast_trend + seasonal_component;
            result.predictions.push_back(prediction);
            
            // Confidence intervals (simplified)
            double se = result.rmse * std::sqrt(1.0 + h * 0.1);
            result.lower_bound.push_back(prediction - 1.96 * se);
            result.upper_bound.push_back(prediction + 1.96 * se);
        }
        
        return result;
    }

private:
    static double CalculateRMSE(const std::vector<double>& actual,
                                 const std::vector<double>& predicted) {
        if (actual.size() != predicted.size() || actual.empty()) {
            return 0.0;
        }
        
        double sum_squared_error = 0.0;
        for (size_t i = 0; i < actual.size(); ++i) {
            double error = actual[i] - predicted[i];
            sum_squared_error += error * error;
        }
        
        return std::sqrt(sum_squared_error / actual.size());
    }
    
    static double CalculateMAPE(const std::vector<double>& actual,
                                const std::vector<double>& predicted) {
        if (actual.size() != predicted.size() || actual.empty()) {
            return 0.0;
        }
        
        double sum_percentage_error = 0.0;
        int count = 0;
        
        for (size_t i = 0; i < actual.size(); ++i) {
            if (actual[i] != 0.0) {
                sum_percentage_error += std::abs((actual[i] - predicted[i]) / actual[i]);
                ++count;
            }
        }
        
        return count > 0 ? (sum_percentage_error / count) * 100.0 : 0.0;
    }
};

// ARIMA model (simplified)
class ARIMA {
public:
    struct Config {
        int p = 1;  // AR order
        int d = 0;  // Differencing order
        int q = 1;  // MA order
    };
    
    static ForecastResult Forecast(
        const std::vector<double>& data,
        int horizon,
        const Config& config = Config()) {
        
        ForecastResult result;
        result.model_type = "ARIMA(" + std::to_string(config.p) + "," +
                           std::to_string(config.d) + "," +
                           std::to_string(config.q) + ")";
        result.confidence_level = 0.95;
        
        if (data.size() < config.p + config.q + 5) {
            return result;
        }
        
        // Apply differencing if needed
        std::vector<double> processed_data = data;
        for (int i = 0; i < config.d; ++i) {
            processed_data = Difference(processed_data);
        }
        
        // Estimate AR coefficients using Yule-Walker
        std::vector<double> ar_coeffs = EstimateARCoefficients(processed_data, config.p);
        
        // Estimate MA coefficients (simplified)
        std::vector<double> ma_coeffs(config.q, 0.5 / config.q);
        
        // Generate forecasts
        std::vector<double> extended = processed_data;
        
        for (int h = 0; h < horizon; ++h) {
            double forecast = 0.0;
            
            // AR component
            for (int i = 0; i < config.p && i < static_cast<int>(extended.size()); ++i) {
                forecast += ar_coeffs[i] * extended[extended.size() - 1 - i];
            }
            
            // MA component (simplified - using zero mean)
            for (int i = 0; i < config.q; ++i) {
                forecast += ma_coeffs[i] * 0.0;  // Assume zero error
            }
            
            extended.push_back(forecast);
            result.predictions.push_back(forecast);
        }
        
        // Reverse differencing
        if (config.d > 0) {
            result.predictions = Integrate(result.predictions, data, config.d);
        }
        
        // Calculate confidence intervals
        double mean_val = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        double variance = 0.0;
        for (double v : data) {
            variance += (v - mean_val) * (v - mean_val);
        }
        variance /= data.size();
        double std_dev = std::sqrt(variance);
        
        for (int h = 0; h < horizon; ++h) {
            double margin = 1.96 * std_dev * std::sqrt(1.0 + h * 0.05);
            result.lower_bound.push_back(result.predictions[h] - margin);
            result.upper_bound.push_back(result.predictions[h] + margin);
        }
        
        // Calculate fit metrics
        std::vector<double> fitted(data.size());
        for (size_t i = config.p; i < data.size(); ++i) {
            fitted[i] = 0.0;
            for (int j = 0; j < config.p; ++j) {
                fitted[i] += ar_coeffs[j] * data[i - j - 1];
            }
        }
        
        result.rmse = CalculateRMSE(data, fitted);
        result.mape = CalculateMAPE(data, fitted);
        
        return result;
    }

private:
    static std::vector<double> Difference(const std::vector<double>& data) {
        std::vector<double> result;
        result.reserve(data.size() - 1);
        for (size_t i = 1; i < data.size(); ++i) {
            result.push_back(data[i] - data[i - 1]);
        }
        return result;
    }
    
    static std::vector<double> Integrate(const std::vector<double>& diff_data,
                                          const std::vector<double>& original,
                                          int order) {
        std::vector<double> result = diff_data;
        
        for (int i = 0; i < order; ++i) {
            double last_value = original.empty() ? 0.0 : original.back();
            for (size_t j = 0; j < result.size(); ++j) {
                result[j] += last_value;
                last_value = result[j];
            }
        }
        
        return result;
    }
    
    static std::vector<double> EstimateARCoefficients(
        const std::vector<double>& data, int p) {
        
        std::vector<double> coeffs(p, 0.0);
        
        if (data.size() < static_cast<size_t>(p) + 1) {
            return coeffs;
        }
        
        // Calculate autocorrelations
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        std::vector<double> autocorr(p + 1, 0.0);
        
        for (int lag = 0; lag <= p; ++lag) {
            for (size_t i = lag; i < data.size(); ++i) {
                autocorr[lag] += (data[i] - mean) * (data[i - lag] - mean);
            }
            autocorr[lag] /= data.size();
        }
        
        if (autocorr[0] == 0.0) {
            return coeffs;
        }
        
        // Yule-Walker equations (simplified for p=1)
        if (p == 1) {
            coeffs[0] = autocorr[1] / autocorr[0];
        } else if (p == 2) {
            double denom = autocorr[0] * autocorr[0] - autocorr[1] * autocorr[1];
            if (denom != 0.0) {
                coeffs[0] = (autocorr[1] * autocorr[0] - autocorr[2] * autocorr[1]) / denom;
                coeffs[1] = (autocorr[0] * autocorr[2] - autocorr[1] * autocorr[1]) / denom;
            }
        }
        
        return coeffs;
    }
    
    static double CalculateRMSE(const std::vector<double>& actual,
                                const std::vector<double>& predicted) {
        if (actual.size() != predicted.size() || actual.empty()) {
            return 0.0;
        }
        
        double sum_squared_error = 0.0;
        int count = 0;
        for (size_t i = 0; i < actual.size(); ++i) {
            if (predicted[i] != 0.0 || actual[i] != 0.0) {
                double error = actual[i] - predicted[i];
                sum_squared_error += error * error;
                ++count;
            }
        }
        
        return count > 0 ? std::sqrt(sum_squared_error / count) : 0.0;
    }
    
    static double CalculateMAPE(const std::vector<double>& actual,
                                const std::vector<double>& predicted) {
        if (actual.size() != predicted.size() || actual.empty()) {
            return 0.0;
        }
        
        double sum_percentage_error = 0.0;
        int count = 0;
        
        for (size_t i = 0; i < actual.size(); ++i) {
            if (actual[i] != 0.0) {
                sum_percentage_error += std::abs((actual[i] - predicted[i]) / actual[i]);
                ++count;
            }
        }
        
        return count > 0 ? (sum_percentage_error / count) * 100.0 : 0.0;
    }
};

// Performance drift detector
class DriftDetector {
public:
    struct DriftResult {
        bool drift_detected;
        size_t drift_point;
        double drift_magnitude;
        std::string drift_type;  // "sudden", "gradual", "recurring"
        double confidence;
    };
    
    // Page-Hinkley test for drift detection
    static DriftResult DetectPageHinkley(
        const std::vector<double>& data,
        double threshold = 50.0,
        double delta = 0.005) {
        
        DriftResult result = {};
        result.drift_detected = false;
        
        if (data.size() < 10) return result;
        
        double mean = data[0];
        double cum_sum = 0.0;
        double min_cum_sum = 0.0;
        
        for (size_t i = 1; i < data.size(); ++i) {
            // Update mean
            mean = mean + (data[i] - mean) / (i + 1);
            
            // Update cumulative sum
            cum_sum += data[i] - mean - delta;
            
            // Update minimum
            if (cum_sum < min_cum_sum) {
                min_cum_sum = cum_sum;
            }
            
            // Check for drift
            if (cum_sum - min_cum_sum > threshold) {
                result.drift_detected = true;
                result.drift_point = i;
                result.drift_magnitude = cum_sum - min_cum_sum;
                result.drift_type = "gradual";
                result.confidence = std::min(result.drift_magnitude / threshold, 1.0);
                break;
            }
        }
        
        return result;
    }
    
    // ADWIN (Adaptive Windowing) algorithm
    static DriftResult DetectADWIN(const std::vector<double>& data,
                                    double delta = 0.002) {
        
        DriftResult result = {};
        result.drift_detected = false;
        
        if (data.size() < 20) return result;
        
        // Simplified ADWIN implementation
        size_t window_start = 0;
        size_t window_size = 10;
        
        while (window_start + window_size * 2 <= data.size()) {
            // Split window into two sub-windows
            double mean1 = 0.0, mean2 = 0.0;
            double var1 = 0.0, var2 = 0.0;
            
            for (size_t i = window_start; i < window_start + window_size; ++i) {
                mean1 += data[i];
            }
            mean1 /= window_size;
            
            for (size_t i = window_start + window_size; 
                 i < window_start + window_size * 2; ++i) {
                mean2 += data[i];
            }
            mean2 /= window_size;
            
            // Calculate variances
            for (size_t i = window_start; i < window_start + window_size; ++i) {
                var1 += (data[i] - mean1) * (data[i] - mean1);
            }
            var1 /= window_size;
            
            for (size_t i = window_start + window_size; 
                 i < window_start + window_size * 2; ++i) {
                var2 += (data[i] - mean2) * (data[i] - mean2);
            }
            var2 /= window_size;
            
            // Check if means are significantly different
            double epsilon = 0.5;  // Simplified threshold
            if (std::abs(mean1 - mean2) > epsilon) {
                result.drift_detected = true;
                result.drift_point = window_start + window_size;
                result.drift_magnitude = std::abs(mean1 - mean2);
                result.drift_type = "sudden";
                result.confidence = std::min(result.drift_magnitude / epsilon, 1.0);
                return result;
            }
            
            window_start += window_size / 2;
        }
        
        return result;
    }
};

// Model selector for best forecasting method
class ForecastingModelSelector {
public:
    struct ModelComparison {
        std::string model_name;
        double rmse;
        double mape;
        double aic;  // Akaike Information Criterion
        double bic;  // Bayesian Information Criterion
    };
    
    static ForecastResult SelectAndForecast(
        const std::vector<double>& data,
        int horizon,
        std::vector<ModelComparison>* comparisons = nullptr) {
        
        std::vector<ModelComparison> results;
        
        // Try different models
        auto ses_result = ExponentialSmoothing::Forecast(
            data, horizon, ExponentialSmoothing::Config{0.3, 0.0, 0.0, 0});
        results.push_back({"SES", ses_result.rmse, ses_result.mape, 0.0, 0.0});
        
        auto holt_result = ExponentialSmoothing::Forecast(
            data, horizon, ExponentialSmoothing::Config{0.3, 0.1, 0.0, 0});
        results.push_back({"Holt", holt_result.rmse, holt_result.mape, 0.0, 0.0});
        
        auto hw_result = ExponentialSmoothing::Forecast(
            data, horizon, ExponentialSmoothing::Config{0.3, 0.1, 0.1, 7});
        results.push_back({"Holt-Winters", hw_result.rmse, hw_result.mape, 0.0, 0.0});
        
        ARIMA::Config arima_config{1, 0, 1};
        auto arima_result = ARIMA::Forecast(data, horizon, arima_config);
        results.push_back({"ARIMA(1,0,1)", arima_result.rmse, arima_result.mape, 0.0, 0.0});
        
        // Select best model (lowest RMSE)
        size_t best_idx = 0;
        double best_rmse = results[0].rmse;
        for (size_t i = 1; i < results.size(); ++i) {
            if (results[i].rmse < best_rmse) {
                best_rmse = results[i].rmse;
                best_idx = i;
            }
        }
        
        if (comparisons) {
            *comparisons = results;
        }
        
        // Return best result
        switch (best_idx) {
            case 0: return ses_result;
            case 1: return holt_result;
            case 2: return hw_result;
            case 3: return arima_result;
            default: return ses_result;
        }
    }
};

} // namespace Analytics
} // namespace Benchmark
