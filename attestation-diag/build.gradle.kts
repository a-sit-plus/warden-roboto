
group = "at.asitplus"
version = "0.0.2"

plugins {
    kotlin("jvm")
    application
    id("at.asitplus.gradle.conventions")
    id("com.github.johnrengelman.shadow")
}

application {
    mainClass.set("at.asitplus.attestation.android.DiagKt")
}

dependencies {
    implementation(project(":android-attestation"))
    implementation("com.google.guava:guava:33.0.0-jre")
    implementation("com.google.code.gson:gson:2.10.1")
}
