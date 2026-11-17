plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.github.maignardi.maigshield.playintegrity"
    compileSdk = 37

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    api(project(":maigshield-core"))
}
