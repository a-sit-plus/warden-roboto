# Android Key Attestation Library
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0) 
[![Kotlin](https://img.shields.io/badge/kotlin-1.8.20-blue.svg?logo=kotlin)](http://kotlinlang.org)
![Java](https://img.shields.io/badge/java-8/11-blue.svg?logo=OPENJDK)
![Build artifacts](https://github.com/a-sit-plus/android-attestation/actions/workflows/gradle-build.yml/badge.svg)
[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus/android-attestation)](https://mvnrepository.com/artifact/at.asitplus/android-attestation/)

This Kotlin library provides a convenient API (a single function, actually) to remotely attest the integrity of an Android device, its OS and a specific application.
It is intended to be integrated into back-end services requiring authentic, unmodified mobile clients (but it also works in other settings, such as peer-to-peer-scenarios).
It is based off [code from Google](https://github.com/google/android-key-attestation) (and actually directly integrates it), such that it can easily keep up with upstream for the lower-level functionality.
Because of this, it only targets the JVM, although a KMP rewrite (also targeting JS/Node) is possible.
This JVM-centricity is also the reason why the function signatures are rather JVM-esque (read: exceptions are thrown on error,
as done by pretty much every verification function of classes form the `java.security` package).

This library is an integral part of the more comprehensive [Attestation Service](https://github.com/a-sit-plus/attestation-service), which also supports iOS clients and provides
more idiomatic kotlin interfaces.
However, if you are only concerned about Android clients, this library provides all functionality needed without unnecessary bloat.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md)

## Background
Android devices with a TEE allow for cryptographic keys to be generated in hardware. These keys can only be used, but not exported and are safe from extraction due protective hardware measures. The Android Keystore API expose this hardware-based management of cryptographic material and also allows for generating certficates for such keys, which contain custom Extension that indicate the location of a key (hardware or software).
<br>
Additional extension (populated by the cryptographic hardware during key generation) further indicate the device's integrity state (bootloader unlocked, system image integrity, …). This certificate is signed in hardware by a manufacturer key (also protected by hardware) which is provisioned during device manufacturing. A certificate corresponding to this manufacurer key is signed by Google, and the public key of this signing key is published by Google.
Hence, verifying this certificate chain against this Google root key makes it possible to assert the authenticity of the leaf certificate. Checking the custom estenstion of this leaf certificate consequently allows for remotely establishing trust in an Android device and the application which created the underlying key.
A noteworthy property of this attestation concept is that no third party needs to be contacted (except for obtaining certificate revocation information) compared to Apple's AppAttest/DeviceCheck.

## Usage

Written in Kotlin, plays nicely with Java (cf. `@JvmOverloads`).

This library is published at maven central.
### Gradle

```kotlin
 dependencies {
     implementation("at.asitplus:android-attestation:$version")
 }
```

The main class is `AndroidAttestationChecker`. Configuration is based on the data class `AttestationConfiguration`. Some properties are nullable – if unset, no checks against these properties are made. 

### Configuration
```kotlin
val checker = AndroidAttestationChecker(
    AndroidAttestationConfiguration(
        packageName = "at.asitplus.demo",           //Application package name
        signatureDigests = someLisfOfByteArrays,    //list of fingerprint of official package signing certificates
        appVersion = 5,                             //minimum app version considered trustworthy (nullable)
        androidVersion = 11000,                     //minimum android version considered to be trustworthy (nullable)
        patchLevel =  PatchLevel(2021, 8),          //minimum patch level (year, month) considered to be trustworthy (nullable)
        requireStrongBox = false,                   //TEE security level is enough, setting this true would require keys to be created within a Titan HSM
        bootloaderUnlockAllowed = false,            //require a locked bootloader to ensure device integrity
        ignoreLeafValidity = false,                 //Whether to ignore the timely validity of the leaf certificate (looking at you, Samsung!)
    )
)
```

The (nullable) properties like patch level and app version essentially allow for excluding outdated devices and obsolete app releases. If, for example a critical flaw is discovered in an attested app, users can be forced to update by considering only the latest and greatest version trustworthy and configuring the `AndroidAttestationChecker` instance accordingly.

In addition, it is possible to override the function which verifies the challenge used to verify an attestation.
By default, this is simply a `contentEquals` on the provided challenge vs a reference value.

### Obtaining an Attestation Result
1. The general workflow this library caters to assumes a back-end service, sending an attestation challenge to the mobile app. This challenge needs to be kept for future reference
2. The app is assumed to generate a key pair with attestation (passing the received challenge the Android Keystore)
3. The app responds with the certificate chain associated with this key pair
4. On the back-end a single call to `AndroidAttestationChecker.verifyAttestation()` is sufficient to remotely verify the app's integrity and establish trust in the app. This call requires the challenge from step 1.

```kotlin
//throws an exception if attestation fails
val atttestationRecord =  checker.verifyAttestation(attestationCertChain, Date(), challengeFromStep1)
```
