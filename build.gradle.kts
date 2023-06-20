import java.io.FileInputStream
import java.util.*

Properties().apply {
    kotlin.runCatching { load(FileInputStream(project.rootProject.file("local.properties"))) }
    forEach { (k, v) -> extra.set(k as String, v) }
}


plugins {
    kotlin("jvm") version "1.8.20"
    id("org.jetbrains.dokka") version "1.7.20"
    id("maven-publish")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    id("signing")
    id("me.champeau.mrjar") version "0.1"
}

multiRelease {
    targetVersions(8, 11)
}

group = "at.asitplus"
version = "0.8.5-SNAPSHOT"



sourceSets.main {
    java {
        srcDirs("${project.rootDir}/src/main/google")
        exclude("com/android/example/")
    }
}

sourceSets.getByName("java11") {
    java {
        srcDirs("${project.rootDir}/android-key-attestation/server/src/main/java")
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
val java11Implementation by configurations.getting
java11Implementation.extendsFrom(configurations.getByName("implementation"))


tasks.dokkaHtml { outputDirectory.set(file("$projectDir/docs")) }
val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
    delete(tasks.dokkaHtml.get().outputDirectory.get())
}

val javadocJar: TaskProvider<Jar> by tasks.registering(Jar::class) {
    dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
    archiveClassifier.set("javadoc")
    from(tasks.dokkaHtml.get().outputDirectory)
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
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
            pom {
                name.set("Android Attestation")
                description.set("Server-Side Android attestation library")
                url.set("https://github.com/a-sit-plus/android-attestation")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/android-attestation.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/android-attestation.git")
                    url.set("https://github.com/a-sit-plus/android-attestation")
                }
            }
        }
    }
}


nexusPublishing {
    repositories {
        sonatype() {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}
