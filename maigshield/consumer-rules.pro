# MaigShield Consumer ProGuard / R8 Rules

# Preserve public SDK API entry points
-keep public class com.maigshield.sdk.MaigShield {
    public *;
}

-keep public class com.maigshield.sdk.MaigShieldConfig {
    public *;
}

-keep public class com.maigshield.sdk.MaigShieldConfig$Builder {
    public *;
}

-keep public enum com.maigshield.sdk.WarmUpMode {
    public *;
}

-keep public class com.maigshield.sdk.network.MaigShieldInterceptor {
    public *;
}

-keep @interface com.maigshield.sdk.network.MaigShieldProtected {
    *;
}

# Preserve Native Bridge and JNI bindings
-keep class com.maigshield.sdk.internal.NativeBridge {
    native <methods>;
    *;
}

# Preserve Honeypot classes and methods intentionally intact
# Reverse engineering tools, Frida scripts and analyzers must see these signatures
-keep class com.maigshield.sdk.internal.honeypot.** {
    public *;
    protected *;
}

# Keep OkHttp Interceptor if OkHttp is present on classpath
-keepnames class com.maigshield.sdk.network.MaigShieldInterceptor implements okhttp3.Interceptor {
    public <methods>;
}

# Retain attributes for cryptographic operations & hardware keystore
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes InnerClasses
-keepattributes EnclosingMethod
