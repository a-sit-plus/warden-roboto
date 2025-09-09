rootProject.name = "WARDEN-roboto-root"

pluginManagement {
    repositories {
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

include("warden-roboto")
include("attestation-diag")

if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("signum")
} else logger.lifecycle("Excluding Signum from this build")
