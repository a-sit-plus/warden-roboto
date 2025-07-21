# 1.0.0

## NEXT
* Attach more context to exceptions

## 1.8.2
* Integrate Google's new PKI cert path validator
    * This provides an additional safety net against cert path manipulation
* Per-App trust anchor overrides
* BEHAVIOURAL CHANGE:
  * Per-App trust anchor overrides changes the order of checks on Android:
    * App-metadata checks are now performed first
    * Consequence: package, signature, … mismatches are reported even before certificate chain validation errors
* More insightful error messages on attestation failure
* Kotlin 2.1.21
* Bouncy Castle 1.81
* KmmResult 1.9.3
* Signum 3.16.3
* Ktor 3.2.0

## 1.8.1
* Optionally disregard attestation statement creation time check by setting `attestationStatementValiditySeconds` to `null`

## 1.8.0

* Dependency Updates
  * Kotlin 2.1.20
  * Kotlinx-Serialization 1.8.0
  * Ktor 3.0.3
* 64-bit precision (`Long`) for temporal offsets and validity -> if you don't want to effectively disable temporal
  attestation validity checks, set offset and validity to ridiculously high values. **THIS IS A BREAKING CHANGE**
* Ability to record debug infos, serialize, deserialize and replay them

## 1.7.2

- Work around upstream bug [#77](https://github.com/google/android-key-attestation/issues/77)
- Dependency Updates:
    - error_prone_annotations 2.36.0
    - guava 33.4.0
    - Ktor 3.0.3

## 1.7.1

- Fix Android version documentation
- Dependency Updates
    - Update to latest Google codebase
    - Update to BC 1.79
    - Kotlin 2.1.0
    - Ktor 3.0.1
    - Kotlinx-Serialization 1.7.3
    - protobuf-javalite 4.28.2

## 1.7.0

- Add `AttestationValueException.Reason.TIME` to indicate too far off or missing attestation statement creation
  time inside the attestation statement (in contrast to Certificate validity issues)
- Add `attestationStatementValiditySeconds` to Android attestation configuration, to set a custom attestation statement
  validity.
  Defaults to 5 minutes (i.e. 300)
- Fix verification time calculation


## 1.6.0

- Rebrand to _WARDEN-roboto_
- Update to latest upstream attestation code
    - `rollbackResistant` -> `rollbackResistance`
    - Dependency Updates
        - Guava: 33.2.1-jre
        - autovalue: 1.11.0
        - protobuf-javalite: 4.27.0

## 1.5.0

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

### 1.5.2

- support HTTP proxy for fetching Android Revocation list
- Dependency Updates:
    - Java 17
    - Kotlin 2.0.0
    - bouncycastle:  1.78.1!!
    - coroutines:    1.8.1
    - datetime:      0.6.0
    - kmmresult:     1.6.1
    - kotest:        5.9.1!!
    - kotlin:        2.0.0
    - ksp:           1.0.22
    - ktor:          2.3.11
    - napier:        2.7.1
    - nexus:         1.3.0
        - serialization: 1.7.1
          **Breaking Changes Ahead!**

### 1.5.1

- dependency updated
- correctly expose guava as api dependency

## 1.4.0

- reorganized constructors for less confusing file-based config loading
- update to latest conventions plugin
- build against JDK11 as per gradle.properties

## 1.3.0

- make configuration play nicely with file-based config loading (e.g. [HopLite](https://github.com/sksamuel/hoplite))

## 1.2.0

- introduce well-defined error codes for every way an attestation can fail
- refactor exception hierarchy as a consequence

### 1.2.1

- make all config classes `data` classes

## 1.1.0

- introduce builder for `AppData`

---

# PRE-1.0

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
