#include "native_sensors.hpp"
#include "syscalls.hpp"

#include <android/looper.h>
#include <algorithm>
#include <chrono>
#include <dlfcn.h>

namespace maigshield::biometrics {

NativeSensorCollector& NativeSensorCollector::instance() {
    static NativeSensorCollector s_instance;
    return s_instance;
}

NativeSensorCollector::NativeSensorCollector() = default;

NativeSensorCollector::~NativeSensorCollector() {
    shutdown();
}

bool NativeSensorCollector::initialize(const char* package_name) {
    if (m_running.load()) {
        return true;
    }

    // Dynamic resolution of ASensorManager_getInstanceForPackage for API >= 26 compatibility
    typedef ASensorManager* (*pfn_getInstanceForPackage)(const char*);
    auto p_getInstanceForPackage = reinterpret_cast<pfn_getInstanceForPackage>(
        dlsym(RTLD_DEFAULT, "ASensorManager_getInstanceForPackage")
    );

    if (p_getInstanceForPackage != nullptr && package_name != nullptr && package_name[0] != '\0') {
        m_sensor_manager = p_getInstanceForPackage(package_name);
    }

    if (!m_sensor_manager) {
        m_sensor_manager = ASensorManager_getInstance();
    }
    if (!m_sensor_manager) {
        return false;
    }

    m_accel_sensor = ASensorManager_getDefaultSensor(m_sensor_manager, ASENSOR_TYPE_ACCELEROMETER);
    m_gyro_sensor = ASensorManager_getDefaultSensor(m_sensor_manager, ASENSOR_TYPE_GYROSCOPE);

    m_running.store(true);
    m_worker_thread = std::thread(&NativeSensorCollector::worker_loop, this);

    return true;
}

void NativeSensorCollector::shutdown() {
    if (!m_running.load()) {
        return;
    }

    m_running.store(false);
    if (m_looper) {
        ALooper_wake(m_looper);
    }

    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }
}

void NativeSensorCollector::start_sampling_window() {
    m_in_touch_window.store(true);
    if (m_event_queue) {
        if (m_accel_sensor) {
            ASensorEventQueue_enableSensor(m_event_queue, m_accel_sensor);
            ASensorEventQueue_setEventRate(m_event_queue, m_accel_sensor, 20000); // 50 Hz
        }
        if (m_gyro_sensor) {
            ASensorEventQueue_enableSensor(m_event_queue, m_gyro_sensor);
            ASensorEventQueue_setEventRate(m_event_queue, m_gyro_sensor, 20000); // 50 Hz
        }
    }
}

void NativeSensorCollector::stop_sampling_window() {
    m_in_touch_window.store(false);
    if (m_event_queue) {
        if (m_accel_sensor) {
            ASensorEventQueue_disableSensor(m_event_queue, m_accel_sensor);
        }
        if (m_gyro_sensor) {
            ASensorEventQueue_disableSensor(m_event_queue, m_gyro_sensor);
        }
    }
}

void NativeSensorCollector::worker_loop() {
    m_looper = ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if (!m_looper || !m_sensor_manager) {
        return;
    }

    m_event_queue = ASensorManager_createEventQueue(m_sensor_manager, m_looper, 1, nullptr, nullptr);
    if (!m_event_queue) {
        return;
    }

    constexpr int max_events = 16;
    ASensorEvent events[max_events];

    while (m_running.load()) {
        int ident = ALooper_pollOnce(50, nullptr, nullptr, nullptr);
        if (ident == 1) {
            ssize_t num_events = 0;
            while ((num_events = ASensorEventQueue_getEvents(m_event_queue, events, max_events)) > 0) {
                std::lock_guard<std::mutex> lock(m_data_mutex);
                for (ssize_t i = 0; i < num_events; ++i) {
                    const ASensorEvent& ev = events[i];
                    if (ev.type == ASENSOR_TYPE_ACCELEROMETER) {
                        double mag = std::sqrt(ev.acceleration.x * ev.acceleration.x +
                                               ev.acceleration.y * ev.acceleration.y +
                                               ev.acceleration.z * ev.acceleration.z);
                        if (m_last_accel_mag > 0.0) {
                            double delta = std::abs(mag - m_last_accel_mag);
                            m_accel_jitter.update(delta);
                        }
                        m_last_accel_mag = mag;
                    } else if (ev.type == ASENSOR_TYPE_GYROSCOPE) {
                        double mag = std::sqrt(ev.vector.x * ev.vector.x +
                                               ev.vector.y * ev.vector.y +
                                               ev.vector.z * ev.vector.z);
                        if (m_last_gyro_mag > 0.0) {
                            double delta = std::abs(mag - m_last_gyro_mag);
                            m_gyro_jitter.update(delta);
                        }
                        m_last_gyro_mag = mag;
                    }
                }
            }
        }
    }

    if (m_event_queue) {
        ASensorManager_destroyEventQueue(m_sensor_manager, m_event_queue);
        m_event_queue = nullptr;
    }
}

void NativeSensorCollector::onTouchDown(float, float, float pressure, float size,
                                        float touch_major, float touch_minor, int32_t device_id) {
    auto now = std::chrono::steady_clock::now();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    {
        std::lock_guard<std::mutex> lock(m_data_mutex);
        m_total_touches++;

        // Detect synthetic touch indicators
        if (device_id <= 0 || pressure <= 0.001f || (size <= 0.001f && touch_major <= 0.001f)) {
            m_synthetic_touch_counter++;
        }

        if (m_last_touch_down_ts > 0) {
            double cadence_delta = static_cast<double>(now_ms - m_last_touch_down_ts);
            m_cadence_stats.update(cadence_delta);
        }
        m_last_touch_down_ts = now_ms;

        m_pressure_stats.update(static_cast<double>(pressure));
        double contact_area = static_cast<double>(touch_major * touch_minor);
        m_touch_size_stats.update(contact_area);
    }

    start_sampling_window();
}

void NativeSensorCollector::onTouchMove(float, float, float pressure, float, float touch_major, float touch_minor) {
    std::lock_guard<std::mutex> lock(m_data_mutex);
    m_pressure_stats.update(static_cast<double>(pressure));
    double contact_area = static_cast<double>(touch_major * touch_minor);
    m_touch_size_stats.update(contact_area);
}

void NativeSensorCollector::onTouchUp(float, float) {
    stop_sampling_window();
}

uint8_t NativeSensorCollector::get_bot_likelihood_score() {
    std::lock_guard<std::mutex> lock(m_data_mutex);

    double score = 0.0;

    // 1. Synthetic touch ratio analysis
    if (m_total_touches > 0) {
        double synthetic_ratio = static_cast<double>(m_synthetic_touch_counter) / static_cast<double>(m_total_touches);
        score += synthetic_ratio * 120.0;
    }

    // 2. Micro-tremor absence analysis
    // Human hand micro-tremor variance is between 0.03 and 0.40 m/s^2.
    // An emulator, virtual clicker, or stationary stand has near-zero variance (< 0.008).
    if (m_accel_jitter.count >= 8) {
        double accel_std = m_accel_jitter.stddev();
        if (accel_std < 0.008) {
            score += 80.0;
        } else if (accel_std < 0.02) {
            score += 40.0;
        }
    }

    // 3. Pressure analog variance
    // Human touch has continuous natural pressure variance.
    // Synthetic touches inject fixed pressure (stddev == 0.0).
    if (m_pressure_stats.count >= 5) {
        double pressure_std = m_pressure_stats.stddev();
        if (pressure_std < 0.001) {
            score += 50.0;
        }
    }

    // 4. Cadence regularity (scripted bot tap intervals)
    if (m_cadence_stats.count >= 4) {
        double cadence_std = m_cadence_stats.stddev();
        if (cadence_std < 3.0) { // Unnatural robotic timing (< 3ms variance)
            score += 60.0;
        }
    }

    score = std::clamp(score, 0.0, 255.0);
    return static_cast<uint8_t>(score);
}

uint8_t NativeSensorCollector::get_duress_tremor_index() {
    std::lock_guard<std::mutex> lock(m_data_mutex);

    double duress = 0.0;

    // Physiological adrenaline-induced tremor (6-14 Hz) increases high-frequency acceleration jitter
    // and erratic angular velocity significantly beyond baseline human levels.
    if (m_accel_jitter.count >= 6) {
        double accel_std = m_accel_jitter.stddev();
        if (accel_std > 0.60) {
            double tremor_excess = std::min((accel_std - 0.60) / 1.50, 1.0);
            duress += tremor_excess * 140.0;
        }
    }

    if (m_gyro_jitter.count >= 6) {
        double gyro_std = m_gyro_jitter.stddev();
        if (gyro_std > 0.80) {
            double gyro_excess = std::min((gyro_std - 0.80) / 2.0, 1.0);
            duress += gyro_excess * 80.0;
        }
    }

    // Erratic contact area fluctuation under panic/coercion
    if (m_touch_size_stats.count >= 6) {
        double area_std = m_touch_size_stats.stddev();
        if (area_std > 50.0) {
            duress += 35.0;
        }
    }

    duress = std::clamp(duress, 0.0, 255.0);
    return static_cast<uint8_t>(duress);
}

} // namespace maigshield::biometrics
