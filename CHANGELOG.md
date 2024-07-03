## 0.1
Initial Release

## 0.2
Validation date can be specified

## 0.3
Throw exception when attestation fails. This way, no logging framework is required to communicate the reason why
attestation failed and the library works nicely with pure java

## 0.5
- More idiomatic Kotlin
- cleaner exception handling
- download revocation list only once per chain

## 0.6 
- maven publishing

## 0.7
- produce jdk8 compatible build (using `jdk8` classifier)

### 0.7.2
- Return ParsedAttestationRecord on Success

### 0.7.3
- Include JavaDoc

### 0.7.4
- More Java-friendly API
- More detailed toplevel error messages on certificate verification fail
- Kotlin 1.8.0

## 0.8
- ability to ignore timely validity of leaf cert

### 0.8.2
- more `@JvmOverloads`

### 0.8.3
- MR Jar Release (Java 11 directly uses code from Google, Java 8 version uses adapted one for legacy support)
- Drop `-jdk8` classifier for proper release to maven central

### 0.8.4
- ability to configure custom trust anchors

### 0.8.5
- updated upstream sources
- cache revocation list

## 0.9.0
- ability to add offset to time of verification (thanks @rolicz)
- fix Java 8 builds (thanks @rolicz)

## 1.0.0
- deprecate MR jar (= remove Java 8 support)
- Build against JDK11
- Kotlin 1.9.22
- Update to latest `android-key-attestation` codebase from Google (2024-01-31)
- Dependency updates:
  - Bouncy Castle 1.77
  - Ktor 2.3.7
  - kotlinx.datetime 0.5.0
  - Napier 2.7.1
  - Guava 33.0.0-jre
  - Error Prone 2.24.1
  - (NEW) AutoValue 1.10.4
### 0.9.2
- drop broken java 8 target
- update sources from upstream

### 0.9.3
- add guava to API for java interop
- kotlin-stdlib API dependency for java interop


## 1.0.0

**This version introduces incompatible changes! Re-read the readme!**

Most notably, it now supports configuring multiple applications, introduces optional software-only attestation and a new hybrid
attestation checker, which caters towards legacy devices, which originally shipped with Android 7 (Nougat).
Most of such devices support hardware attestation only for keys, but not for app/os-related information.
<br>
Moreover, a builder is now available for more Java-friendliness

In addition, 1.0.0. introduces a new diagnostics tool (a runnable jar), which takes an attestation certificate and prints
out the attestation record.

### 1.1.0
- introduce builder for `AppData`

### 1.2.0
- introduce well-defined error codes for every way an attestation can fail
- refactor exception hierarchy as a consequence

#### 1.2.1
- make all config classes `data` classes

### 1.3.0
- make configuration play nicely with file-based config loading (e.g. [HopLite](https://github.com/sksamuel/hoplite))

### 1.4.0
- reorganized constructors for less confusing file-based config loading
- update to latest conventions plugin
- build against JDK11 as per gradle.properties

### 1.5.0
- Kotlin 1.9.22
- Update to latest `android-key-attestation` codebase from Google (2024-01-31)
- Dependency updates:
  - Bouncy Castle 1.77
  - Ktor 2.3.7
  - kotlinx.datetime 0.5.0
  - Napier 2.7.1
  - Guava 33.0.0-jre
  - Error Prone 2.24.1
  - (NEW) AutoValue 1.10.4

#### 1.5.1
- dependency updated
- correctly expose guava as api dependency

#### 1.5.2
- support HTTP proxy for fetching Android Revocation list
- Dependency Updates:
  -  Java 17
  -  Kotlin 2.0.0
  -  bouncycastle:  1.78.1!!
  -  coroutines:    1.8.1
  -  datetime:      0.6.0
  -  kmmresult:     1.6.1
  -  kotest:        5.9.1!!
  -  kotlin:        2.0.0
  -  ksp:           1.0.22
  -  ktor:          2.3.11
  -  napier:        2.7.1
  -  nexus:         1.3.0
  -  serialization: 1.7.1