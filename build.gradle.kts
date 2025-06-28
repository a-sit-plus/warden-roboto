plugins {
    id("io.kotest.multiplatform") version "6.0.0.M4" apply false //we're JVM-only so apply false. but we need the plugin in the classpath until I clean up the conventions plugins
    kotlin("jvm") version "2.1.21" apply false
    kotlin("plugin.serialization") version "2.1.21" apply false
    id("at.asitplus.gradle.conventions") version "20250628"
}

group = "at.asitplus"

//work around nexus publish bug
val artifactVersion: String by extra
version = artifactVersion
//end work around nexus publish bug