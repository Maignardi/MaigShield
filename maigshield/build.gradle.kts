import com.vanniktech.maven.publish.AndroidSingleVariantLibrary

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.vanniktech.maven.publish)
}

android {
    namespace = "com.maigshield.sdk"
    compileSdk = 37

    defaultConfig {
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters.addAll(setOf("arm64-v8a", "x86_64"))
        }

        externalNativeBuild {
            cmake {
                cppFlags.addAll(
                    listOf(
                        "-std=c++20",
                        "-fexceptions",
                        "-frtti",
                        "-fvisibility=hidden",
                        "-fvisibility-inlines-hidden",
                        "-fstack-protector-strong",
                        "-D_FORTIFY_SOURCE=2",
                        "-Wformat",
                        "-Wformat-security",
                        "-Wall",
                        "-Wextra",
                        "-O2"
                    )
                )
                arguments.addAll(
                    listOf(
                        "-DANDROID_STL=c++_static",
                        "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                    )
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            variant = "release",
            sourcesJar = true,
            publishJavadocJar = true
        )
    )

    coordinates(
        groupId = providers.gradleProperty("GROUP").get(),
        artifactId = "maigshield",
        version = providers.gradleProperty("VERSION_NAME").get()
    )

    publishToMavenCentral(automaticRelease = true)
    signAllPublications()

    pom {
        name.set("MaigShield")
        description.set(
            "Zero-Boolean Android RASP, anti-trojan, native C++20 NDK behavioral biometrics, and StrongBox hardware key attestation SDK."
        )
    }
}

tasks.withType<org.gradle.plugins.signing.Sign>().configureEach {
    val hasSigningKey = providers.gradleProperty("signingInMemoryKey").isPresent ||
        !System.getenv("ORG_GRADLE_PROJECT_signingInMemoryKey").isNullOrBlank() ||
        providers.gradleProperty("signing.keyId").isPresent
    val isLocalOnly = gradle.startParameter.taskNames.isNotEmpty() &&
        gradle.startParameter.taskNames.all { it.endsWith("publishToMavenLocal") }
    onlyIf { hasSigningKey || !isLocalOnly }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    compileOnly(libs.okhttp)

    testImplementation(libs.junit)
    testImplementation(libs.okhttp)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
