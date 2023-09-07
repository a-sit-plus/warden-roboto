
group = "at.asitplus"
version = "0.0.1"

plugins {
    kotlin("jvm")
    application
    id("at.asitplus.gradle.conventions")
    id("com.github.johnrengelman.shadow")
}

kotlin{
    jvmToolchain(11)
}
application {
    mainClass.set("at.asitplus.attestation.android.DiagKt")
}

dependencies {
    implementation(project(":android-attestation"))
    implementation("com.google.code.gson:gson:2.10.1")
}
