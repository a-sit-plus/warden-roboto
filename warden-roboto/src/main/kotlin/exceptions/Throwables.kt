package at.asitplus.attestation.android.exceptions

import at.asitplus.attestation.android.SoftwareAttestationChecker

/**
 * Base class for all well-defined Android attestation exceptions.
 * If this one is thrown, a well-defined error arose.
 */
abstract class AndroidAttestationException(message: String?, cause: Throwable?):Throwable(message, cause)


/**
 * Indicates an attestation error during App or OS attestation
 *
 * @param message the error message
 * @param cause the underlying exception
 * @param reason one of a set of well-defined [Reason]s why the attestation failed
 */
class AttestationValueException(message: String?, cause: Throwable? = null, val reason: Reason) : AndroidAttestationException(message, cause) {

    /**
     * Possible reasons an [AttestationValueException] was thrown
     */
    enum class Reason {
        /**
         * Indicates an unlocked bootloader and/or modified system image
         */
        SYSTEM_INTEGRITY,

        /**
         * Indicates that the app was not signed by the developer (i.e. a repackaged app has been detected9
         */
        APP_SIGNER_DIGEST,

        /**
         * Indicates that "this is not the app you are looking for" (i.e. an unauthorized client is connecting to your backend)
         */
        PACKAGE_NAME,

        /**
         * Indicates an app version mismatch (i.e. the app used is too old)
         */
        APP_VERSION,

        /**
         * Indicates an unexpected error when trying to attest an app's properties. This should never happen, but a borked
         * attestation extension in the leaf certificate coul cause this.
         */
        APP_UNEXPECTED,

        /**
         * Indicates an unsupported (i.e. outdated) OS or patch level version being used.
         */
        OS_VERSION,

        /**
         * If you encounter this, you are assumed to know what it is about
         */
        ROLLBACK_RESISTANCE,

        /**
         * Happens if the challenge in the attestation record does not pass the challenge verification function
         * (which, by default, simply checks for equality)
         */
        CHALLENGE,

        /**
         * Indicates that the security level of the attestation does not match the configured one (i.e. an attestation
         * record produced in hardware being validated against a [SoftwareAttestationChecker].
         *
         * **Note** that this reason might be shadowed by a [CertificateInvalidException] with [CertificateInvalidException.Reason.TRUST]
         * since software and hardware attestation use different trust anchors
         */
        SEC_LEVEL
    }
}

/**
 * Indicates an error verifying the attestation's underlying certificate chain
 *
 * @param message the error message
 * @param cause the underlying exception
 * @param reason one of a set of well-defined [Reason]s why the attestation failed
 */
class CertificateInvalidException(message: String, cause: Throwable? = null, val reason: Reason) :
    AndroidAttestationException(message, cause) {

    /**
     * Possible reasons a [CertificateInvalidException] was thrown
     */
    enum class Reason {
        /**
         * Indicates either a borked certificate chain, or a mismatching trust anchor
         */
        TRUST,

        /**
         * Indicates that temporal invalidity of at least one certificate
         */
        TIME,

    }
}

/**
 * Indicates an attestation error due to revocation or inability to fetch a revocation list
 * @param message the error message
 * @param cause the underlying exception
 * @param reason one of a set of well-defined [Reason]s why the attestation failed
 */
class RevocationException(message: String?, cause: Throwable? = null, val reason: Reason) : AndroidAttestationException(message, cause) {

    /**
     * Possible reasons, a [RevocationException] was thrown
     */
    enum class Reason {

        /**
         * Indicates an error fetching the revocation list.
         */
        LIST_UNAVAILABLE,

        /**
         * Indicates that a certificate on the chain was revoked or suspended.
         */
        REVOKED
    }
}
