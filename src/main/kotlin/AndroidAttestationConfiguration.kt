package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException

/**
 * Nomen est omen
 */
data class PatchLevel(val year: Int, val month: Int)

/**
 * Main Android Key attestation configuration class serving as ground truth for all key attestation verifications
 */

class AndroidAttestationConfiguration @JvmOverloads constructor(
    /**
     * Android app package name (e.g. `at.asitplus.keyattestationdemio`)
     */
    val packageName: String,
    /**
     * SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
     * production play store releases.
     * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
     */
    val signatureDigests: List<ByteArray>,

    /**
     * optional parameter. If set, attestation enforces application version to be greater or equal to this parameter
     */
    val appVersion: Int? = null,

    /**
     * optional parameter If set, attestation enforces Android version to be greater or equal to this parameter.
     * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
     */
    val androidVersion: Int? = null,

    /**
     * optional parameter If set, attestation enforces Security patch level to be greater or equal to this parameter.
     */
    patchLevel: PatchLevel? = null,

    /**
     * Set to `true` if *StrongBox* security level should be required
     */
    val requireStrongBox: Boolean = false,

    /**
     * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
     * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
     */
    val bootloaderUnlockAllowed: Boolean = false,

    /**
     * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
     */
    val requireRollbackResistance: Boolean = false,

    /**
     * Whether to ignore the timely validity of the leaf certificate
     */
    val ignoreLeafValidity: Boolean = false,
) {

    /**
     * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
     */
    val osPatchLevel: Int? = patchLevel?.let { "%04d".format(it.year) + "%02d".format(it.month) }?.toInt()

    init {
        if (signatureDigests.isEmpty()) throw AttestationException("No signature digests specified")
    }
}