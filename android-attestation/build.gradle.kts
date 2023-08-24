import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.ktor
import org.gradle.kotlin.dsl.support.listFilesOrdered

group = "at.asitplus"
version = "0.9.0"

plugins {
    kotlin("jvm")
    id("maven-publish")
    id("org.jetbrains.dokka")
    id("signing")
    id("me.champeau.mrjar") version "0.1"
    id("at.asitplus.gradle.conventions")
}


multiRelease {
    targetVersions(8, 11)
}

tasks.getByName<Test>("test") {
    val javaToolchains = project.extensions.getByType<JavaToolchainService>()
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(11))
    })
}


sourceSets.main {
    java {
        srcDirs("${projectDir}/src/main/google")
        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java"
        )
    }
}

sourceSets.getByName("java11") {
    java {
        srcDirs("${project.rootDir}/android-key-attestation/server/src/main/java")
        exclude(
            "com/android/example/",
            "com/google/android/attestation/CertificateRevocationStatus.java"
        )
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

    testImplementation(ktor("client-mock"))
    implementation(bouncycastle("bcpkix","jdk18on"))
    implementation(ktor("client-core"))
    implementation(ktor("client-content-negotiation"))
    implementation(ktor("serialization-kotlinx-json"))
    implementation(ktor("client-cio"))
    implementation("com.google.errorprone:error_prone_annotations:2.3.1")
    implementation("com.google.guava:guava:32.1.2-jre")
}


tasks.test {
    useJUnitPlatform()
}
val java11Implementation by configurations.getting
java11Implementation.extendsFrom(configurations.getByName("implementation"))


//No, it's not pretty! Yes it's fragile! But it also works perfectly well when run from a GitHub actions and that's what counts
tasks.dokkaHtml {

    val moduleDesc = File("$rootDir/dokka-tmp.md").also { it.createNewFile() }
    val readme =
        File("${rootDir}/README.md").readText().replaceFirst("# ", "")
    val moduleTitle = readme.lines().first()
    moduleDesc.writeText("# Module $readme")
    moduleName.set(moduleTitle)

    dokkaSourceSets {
        named("main") {

            includes.from(moduleDesc)
        }
    }
    outputDirectory.set(file("${rootDir}/docs"))
    doLast {
        rootDir.listFilesOrdered { it.extension.lowercase() == "png" || it.extension.lowercase() == "svg" }
            .forEach { it.copyTo(File("$rootDir/docs/${it.name}"), overwrite = true) }
    }
}

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
    repositories {
        mavenLocal()
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
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
