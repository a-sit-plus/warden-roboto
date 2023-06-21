rootProject.name = "android-attestation-root"

pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "apsConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("android-attestation")
