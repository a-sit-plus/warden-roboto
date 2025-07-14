
group = "at.asitplus"
version = "0.0.3"

plugins {
    kotlin("jvm")
    application
    id("at.asitplus.gradle.conventions")
    id("com.gradleup.shadow")
}

application {
    mainClass.set("at.asitplus.attestation.android.DiagKt")
}

sourceSets.main {
    java {
        srcDirs("${project.rootDir}/android-key-attestation/src/main/java")

        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java",
        )
        //TODO: remove this and the patched source file in our tree once https://github.com/google/android-key-attestation/issues/77 is fixed
        File("${project.rootDir}/android-key-attestation/src/main/java/com/google/android/attestation/AuthorizationList.java").let {
            if (it.exists()) {
                it.renameTo(File(it.canonicalPath + ".bak"))
            }
        }
    }
}


dependencies {
    implementation(project(":warden-roboto"))
    implementation("com.google.auto.value:auto-value-annotations:1.11.0")
    implementation("com.google.code.gson:gson:2.12.1")
    implementation("at.asitplus.signum:indispensable:3.16.3") {
        exclude("org.bouncycastle", "bcpkix-jdk18on")
    }
}
