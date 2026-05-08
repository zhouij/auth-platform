
plugins {
    alias(libs.plugins.spring.boot) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.spring) apply false
}

subprojects {
    repositories {
        mavenCentral()
    }
}

allprojects {
    group = "com.authplatform"
    version = "1.0.0-SNAPSHOT"
}
