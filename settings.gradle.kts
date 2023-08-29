rootProject.name = "android-attestation-root"

pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
        mavenCentral()
        gradlePluginPortal()
    }
}

include("android-attestation")
