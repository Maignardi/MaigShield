#pragma once

#include <cstdint>
#include <cmath>
#include <mutex>
#include <atomic>
#include <thread>
#include <android/sensor.h>

namespace maigshield::biometrics {

struct WelfordAccumulator {
    uint64_t count{0};
    double mean{0.0};
    double M2{0.0};

    void update(double x) noexcept {
        count++;
        double delta = x - mean;
        mean += delta / static_cast<double>(count);
        double delta2 = x - mean;
        M2 += delta * delta2;
    }

    [[nodiscard]] double variance() const noexcept {
        return (count > 1) ? (M2 / static_cast<double>(count - 1)) : 0.0;
    }

    [[nodiscard]] double stddev() const noexcept {
        double v = variance();
        return (v > 0.0) ? std::sqrt(v) : 0.0;
    }

    void reset() noexcept {
        count = 0;
        mean = 0.0;
        M2 = 0.0;
    }
};

class NativeSensorCollector {
public:
    static NativeSensorCollector& instance();

    bool initialize(const char* package_name = nullptr);
    void shutdown();

    // Touch event registration from UI layer
    void onTouchDown(float x, float y, float pressure, float size, float touch_major, float touch_minor, int32_t device_id);
    void onTouchMove(float x, float y, float pressure, float size, float touch_major, float touch_minor);
    void onTouchUp(float x, float y);

    // Compute final biometrics indices (0..255)
    uint8_t get_bot_likelihood_score();
    uint8_t get_duress_tremor_index();

private:
    NativeSensorCollector();
    ~NativeSensorCollector();

    void start_sampling_window();
    void stop_sampling_window();
    void worker_loop();

    ASensorManager* m_sensor_manager{nullptr};
    const ASensor* m_accel_sensor{nullptr};
    const ASensor* m_gyro_sensor{nullptr};
    ASensorEventQueue* m_event_queue{nullptr};
    ALooper* m_looper{nullptr};

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_in_touch_window{false};
    std::thread m_worker_thread;

    std::mutex m_data_mutex;
    WelfordAccumulator m_accel_jitter;
    WelfordAccumulator m_gyro_jitter;
    WelfordAccumulator m_pressure_stats;
    WelfordAccumulator m_touch_size_stats;
    WelfordAccumulator m_cadence_stats;

    double m_last_accel_mag{0.0};
    double m_last_gyro_mag{0.0};
    int64_t m_last_touch_down_ts{0};
    uint32_t m_synthetic_touch_counter{0};
    uint32_t m_total_touches{0};
};

} // namespace maigshield::biometrics
