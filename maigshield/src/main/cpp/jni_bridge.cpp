#include <jni.h>
#include <string>
#include <vector>

#include "integrity_scanner.hpp"
#include "native_sensors.hpp"
#include "token_packer.hpp"
#include "obfuscate.hpp"

using namespace maigshield::integrity;
using namespace maigshield::biometrics;
using namespace maigshield::packer;

static jboolean native_init(JNIEnv* env, jclass, jstring pkg_name, jlong initial_counter) {
    const char* c_pkg = nullptr;
    if (pkg_name != nullptr) {
        c_pkg = env->GetStringUTFChars(pkg_name, nullptr);
    }

    bool sensors_ok = NativeSensorCollector::instance().initialize(c_pkg);
    if (c_pkg != nullptr) {
        env->ReleaseStringUTFChars(pkg_name, c_pkg);
    }

    if (initial_counter > 0) {
        TokenPacker::set_initial_counter(static_cast<uint64_t>(initial_counter));
    }

    return sensors_ok ? JNI_TRUE : JNI_FALSE;
}

static jlong native_scan_integrity(JNIEnv* env, jclass) {
    return static_cast<jlong>(IntegrityScanner::scan_all(env));
}

static jbyteArray native_pack_envelope(JNIEnv* env, jclass, jlong java_threat_flags, jbyteArray binding_hash) {
    uint64_t native_flags = IntegrityScanner::scan_all(env);
    uint64_t total_flags = native_flags | static_cast<uint64_t>(java_threat_flags);

    uint8_t bot_score = NativeSensorCollector::instance().get_bot_likelihood_score();
    uint8_t duress_score = NativeSensorCollector::instance().get_duress_tremor_index();

    const uint8_t* hash_bytes = nullptr;
    jbyte* pinned_hash = nullptr;
    if (binding_hash != nullptr && env->GetArrayLength(binding_hash) == 32) {
        pinned_hash = env->GetByteArrayElements(binding_hash, nullptr);
        hash_bytes = reinterpret_cast<const uint8_t*>(pinned_hash);
    }

    std::vector<uint8_t> envelope = TokenPacker::pack_envelope(
        total_flags,
        bot_score,
        duress_score,
        hash_bytes
    );

    if (pinned_hash != nullptr) {
        env->ReleaseByteArrayElements(binding_hash, pinned_hash, JNI_ABORT);
    }

    jbyteArray result = env->NewByteArray(static_cast<jsize>(envelope.size()));
    if (result != nullptr) {
        env->SetByteArrayRegion(
            result,
            0,
            static_cast<jsize>(envelope.size()),
            reinterpret_cast<const jbyte*>(envelope.data())
        );
    }

    TokenPacker::secure_scrub(envelope.data(), envelope.size());
    return result;
}

static void native_on_touch_down(JNIEnv*, jclass, jfloat x, jfloat y, jfloat pressure,
                                 jfloat size, jfloat touch_major, jfloat touch_minor, jint device_id) {
    NativeSensorCollector::instance().onTouchDown(x, y, pressure, size, touch_major, touch_minor, device_id);
}

static void native_on_touch_move(JNIEnv*, jclass, jfloat x, jfloat y, jfloat pressure,
                                 jfloat size, jfloat touch_major, jfloat touch_minor) {
    NativeSensorCollector::instance().onTouchMove(x, y, pressure, size, touch_major, touch_minor);
}

static void native_on_touch_up(JNIEnv*, jclass, jfloat x, jfloat y) {
    NativeSensorCollector::instance().onTouchUp(x, y);
}

static jint native_get_bot_score(JNIEnv*, jclass) {
    return static_cast<jint>(NativeSensorCollector::instance().get_bot_likelihood_score());
}

static jint native_get_duress_score(JNIEnv*, jclass) {
    return static_cast<jint>(NativeSensorCollector::instance().get_duress_tremor_index());
}

static void native_trigger_honeypot(JNIEnv*, jclass, jint honeypot_id) {
    IntegrityScanner::trigger_honeypot(static_cast<uint32_t>(honeypot_id));
}

static jlong native_unscramble_flags(JNIEnv*, jclass, jlong scrambled, jlong salt, jlong ts, jint code_checksum) {
    uint64_t raw = TokenPacker::unscramble_flags(
        static_cast<uint64_t>(scrambled),
        static_cast<uint64_t>(salt),
        static_cast<uint64_t>(ts),
        static_cast<uint32_t>(code_checksum)
    );
    return static_cast<jlong>(raw);
}

static jint native_get_code_checksum(JNIEnv*, jclass) {
    return static_cast<jint>(IntegrityScanner::calculate_code_checksum());
}

static const JNINativeMethod g_methods[] = {
    {
        "nativeInit",
        "(Ljava/lang/String;J)Z",
        reinterpret_cast<void*>(native_init)
    },
    {
        "nativeScanIntegrity",
        "()J",
        reinterpret_cast<void*>(native_scan_integrity)
    },
    {
        "nativePackEnvelope",
        "(J[B)[B",
        reinterpret_cast<void*>(native_pack_envelope)
    },
    {
        "nativeOnTouchDown",
        "(FFFFFFI)V",
        reinterpret_cast<void*>(native_on_touch_down)
    },
    {
        "nativeOnTouchMove",
        "(FFFFFF)V",
        reinterpret_cast<void*>(native_on_touch_move)
    },
    {
        "nativeOnTouchUp",
        "(FF)V",
        reinterpret_cast<void*>(native_on_touch_up)
    },
    {
        "nativeGetBotScore",
        "()I",
        reinterpret_cast<void*>(native_get_bot_score)
    },
    {
        "nativeGetDuressScore",
        "()I",
        reinterpret_cast<void*>(native_get_duress_score)
    },
    {
        "nativeTriggerHoneypot",
        "(I)V",
        reinterpret_cast<void*>(native_trigger_honeypot)
    },
    {
        "nativeUnscrambleFlags",
        "(JJJI)J",
        reinterpret_cast<void*>(native_unscramble_flags)
    },
    {
        "nativeGetCodeChecksum",
        "()I",
        reinterpret_cast<void*>(native_get_code_checksum)
    }
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }

    if (IntegrityScanner::verify_jni_env(env)) {
        IntegrityScanner::trigger_honeypot(63); // Marker for corrupted JNI interface
    }

    OBFUSCATE_STACK(cls_name, "com/maigshield/sdk/internal/NativeBridge");
    jclass clazz = env->FindClass(cls_name.c_str());
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    jint reg_result = env->RegisterNatives(
        clazz,
        g_methods,
        sizeof(g_methods) / sizeof(g_methods[0])
    );
    env->DeleteLocalRef(clazz);

    if (reg_result != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
