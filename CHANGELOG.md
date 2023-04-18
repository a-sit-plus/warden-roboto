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