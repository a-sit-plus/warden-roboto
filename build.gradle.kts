import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.io.FileInputStream
import java.util.*

val jdk8: String? = project.properties["jdk8"] as String?
val useJdk8 by lazy { jdk8 == "true" }

plugins {
    id("maven-publish")
    kotlin("jvm") version "1.8.20"
    id("org.jetbrains.dokka") version "1.7.20"
}

group = "at.asitplus"
version = "0.8.1"

Properties().apply {
    kotlin.runCatching { load(FileInputStream(project.rootProject.file("local.properties"))) }
    forEach { (k, v) -> extra.set(k as String, v) }
}

sourceSets.main {
    java {
        srcDirs(
            if (useJdk8) "${project.rootDir}/src/main/google"
            else "${project.rootDir}/android-key-attestation/server/src/main/java"
        )
        exclude("com/android/example/")
    }

}

sourceSets.test {
    /* cursed workaround for including this very same source directory in another project when using this project
    for composite builds */
    kotlin {
        srcDir("src/test/kotlin/data")
    }
}

val dokkaHtml by tasks.getting(org.jetbrains.dokka.gradle.DokkaTask::class)

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(dokkaHtml)
    archiveClassifier.set((if (useJdk8) "jdk8-" else "") + "javadoc")
    from(dokkaHtml.outputDirectory)
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = if (useJdk8) "1.8" else "11"
}
tasks.compileJava {
    options.release.set(if (useJdk8) 8 else 11)
}

dependencies {
    testImplementation("io.kotest:kotest-runner-junit5:5.5.4")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.73")
    implementation("com.google.code.gson:gson:2.10")
    implementation("com.squareup.okhttp3:okhttp:4.10.0")
    implementation("com.google.errorprone:error_prone_annotations:2.3.1")
    implementation("com.google.guava:guava:30.0-jre")
}


tasks.test {
    useJUnitPlatform()
}


val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set((if (useJdk8) "jdk8-" else "") + "sources")
    from(sourceSets.main.get().allSource)
}

tasks.jar {
    if (useJdk8) archiveClassifier.set("jdk8")
}

repositories {
    mavenCentral()
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(sourcesJar.get())
            artifact(javadocJar.get())
        }
    }
}
