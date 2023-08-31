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
- More Java-freindly API
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

### 0.9.2
- drop broken java 8 target
- update sources from upstream