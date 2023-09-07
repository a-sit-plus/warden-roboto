package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException
import com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Nomen est omen
 */
data class PatchLevel(val year: Int, val month: Int) {
    val asSingleInt: Int by lazy {
        ("%04d".format(year) + "%02d".format(month)).toInt()
    }
}

/**
 * Default trust anchors used to verify hardware attestation
 */
val DEFAULT_HARDWARE_TRUST_ANCHORS = arrayOf(
    KeyFactory.getInstance("RSA")
        .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY)))
)


/**
 * Default trust anchors used to verify software attestation
 */
val DEFAULT_SOFTWARE_TRUST_ANCHORS = arrayOf(
    KeyFactory.getInstance("EC")
        .generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(SoftwareAttestationChecker.GOOGLE_SOFTWARE_EC_ROOT))
        ),
    KeyFactory.getInstance("RSA")
        .generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder().decode(SoftwareAttestationChecker.GOOGLE_SOFTWARE_RSA_ROOT)
            )
        )
)

/**
 * Main Android Key attestation configuration class serving as ground truth for all key attestation verifications.
 *
 * @param packageNames Android app package name (e.g. `at.asitplus.demo`)
 * @param signatureDigests SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing
 * certificate for production play store releases. Being able to specify multiple digests makes it easy to use development
 * builds and production builds in parallel.
 * @param appVersion optional parameter. If set, attestation enforces application version to be greater or equal to this parameter
 * @param patchLevel optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter
 * @param requireStrongBox Set to `true` if *StrongBox* security level should be required
 * @param bootloaderUnlockAllowed Set to true if unlocked bootloaders should be allowed.
 * **Attention:** Allowing unlocked bootloaders in production effectively defeats the purpose of Key Attestation.
 * Useful for debugging/testing
 * @param requireRollbackResistance Unsupported by most devices.
 * See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
 * @param ignoreLeafValidity Whether to ignore the timely validity of the leaf certificate (looking at you, Samsung!)
 * @param hardwareAttestationTrustAnchors Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
 * Overriding this list is useful for automated end-to-end tests, for example.
 *
 */

class AndroidAttestationConfiguration @JvmOverloads constructor(

    /**
     * List of applications, which can be attested
     */
    val applications: List<AppData>,

    /**
     * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
     * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
     * Can be overridden for individual apps
     */
    val androidVersion: Int? = null,

    /**
     * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
     * Can be overridden for individual apps.
     */
    patchLevel: PatchLevel? = null,

    /**
     * Set to `true` if *StrongBox* security level should be required.
     * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
     */
    val requireStrongBox: Boolean = false,

    /**
     * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
     * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
     * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
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

    /**
     * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
     * Overriding this list is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
     */
    val hardwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS),

    /**
     * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
     * Overriding this list is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
     */
    val softwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS),

    /**
     *  Tolerance in seconds added to verification date
     */
    val verificationSecondsOffset: Int = 0,

    /**
     * Entirely disable creation of a [HardwareAttestationChecker]. Only change this flag, if you **really** know what
     * you are doing!
     * @see enableSoftwareAttestation
     */
    val disableHardwareAttestation: Boolean = false,

    /**
     * Enables hybrid attestation. A [NougatHybridAttestationChecker] can only be instantiated if this flag is set to true.
     * Only change this flag, if you requre support for devices, which originally shipped with Android 7 (Nougat), as these
     * devices only support hardware-backed key attestation, but provide no indication about the OS state.
     * Hence, app-attestation cannot be trusted, but key attestation can.
     */
    val enableNougatAttestation: Boolean = false,

    /**
     * Enables software attestation. A [SoftwareAttestationChecker] can only be instantiated if this flag is set to true.
     * Only change this flag, if you **really** know what you are doing!
     * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
     * [HardwareAttestationChecker] and a [SoftwareAttestationChecker].
     */
    val enableSoftwareAttestation: Boolean = false,

    ) {

    /**
     * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
     */
    val osPatchLevel: Int? = patchLevel?.asSingleInt

    /**
     * Specifies a to-be attested app
     */
    class AppData @JvmOverloads constructor(
        /**
         * Android app package name (e.g. `at.asitplus.demo`)
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
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
         */
        val androidVersionOverride: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         */
        patchLevelOverride: PatchLevel? = null,

        ) {
        init {
            if (signatureDigests.isEmpty()) throw AttestationException("No signature digests specified")
        }

        /**
         * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
         */
        val osPatchLevel: Int? = patchLevelOverride?.asSingleInt

    }

    init {
        if (hardwareAttestationTrustAnchors.isEmpty() && softwareAttestationTrustAnchors.isEmpty())
            throw AttestationException("No trust anchors configured")

        if (applications.isEmpty()) throw AttestationException("No apps configured")
        if (disableHardwareAttestation && !enableSoftwareAttestation && !enableNougatAttestation)
            throw AttestationException("Neither hardware, nor hybrid, nor software attestation enabled")
    }

    /**
     * Builder to construct an [AndroidAttestationConfiguration] in a java-friendly way
     * @param applications applications to be attested
     */
    class Builder(private val applications: List<AppData>) {

        /**
         * convenience constructor to attest a [singleApp]
         */
        constructor(singleApp: AppData) : this(listOf(singleApp))

        private var androidVersion: Int? = null
        private var patchLevel: PatchLevel? = null
        private var requireStrongBox: Boolean = false
        private var bootloaderUnlockAllowed: Boolean = false
        private var rollbackResitanceRequired: Boolean = false
        private var ignoreLeafValidity: Boolean = false
        private var hardwareAttestationTrustAnchors = mutableSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS)

        private var softwareAttestationTrustAnchors = mutableSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS)

        private var verificationSecondsOffset = 0

        private var disableHwAttestation: Boolean = false
        private var enableSwAttestation: Boolean = false
        private var enableNougatAttestation: Boolean = false

        /**
         * specifies a minimum Android version
         * @see AndroidAttestationConfiguration.androidVersion
         */
        fun androidVersion(version: Int) = apply { androidVersion = version }

        /**
         * @see PatchLevel
         */
        fun patchLevel(lvl: PatchLevel) = apply { patchLevel = lvl }

        /**
         * @see AndroidAttestationConfiguration.requireStrongBox
         */
        fun requireStrongBox() = apply { requireStrongBox = true }

        /**
         * @see AndroidAttestationConfiguration.bootloaderUnlockAllowed
         */
        fun allowBootloaderUnlock() = apply { bootloaderUnlockAllowed = true }

        /**
         * @see AndroidAttestationConfiguration.requireRollbackResistance
         */
        fun requireRollbackResistance() = apply { rollbackResitanceRequired = true }

        /**
         * @see AndroidAttestationConfiguration.ignoreLeafValidity
         */
        fun ingoreLeafValidity() = apply { ignoreLeafValidity = true }

        /**
         * @see AndroidAttestationConfiguration.hardwareAttestationTrustAnchors
         */
        fun hardwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { hardwareAttestationTrustAnchors.apply { clear(); addAll(anchors) } }

        /**
         * adds a single hardware attestation trust anchor
         * @see AndroidAttestationConfiguration.hardwareAttestationTrustAnchors
         */
        fun addHardwareAttestationTurstAnchor(anchor: PublicKey) = apply { hardwareAttestationTrustAnchors += anchor }

        /**
         * @see AndroidAttestationConfiguration.softwareAttestationTrustAnchors
         */
        fun softwareAttestationTrustAnchors(anchors: Set<PublicKey>) =
            apply { softwareAttestationTrustAnchors.apply { clear(); addAll(anchors) } }

        /**
         * adds a single software attestation trust anchor
         * @see AndroidAttestationConfiguration.softwareAttestationTrustAnchors
         */
        fun addSoftwareAttestationTrustAnchor(anchor: PublicKey) = apply { softwareAttestationTrustAnchors += anchor }

        /**
         * @see AndroidAttestationConfiguration.verificationSecondsOffset
         */
        fun verificationSecondsOffset(seconds: Int) = apply { verificationSecondsOffset = seconds }

        /**
         * @see AndroidAttestationConfiguration.disableHardwareAttestation
         */
        fun disableHardwareAttestation() = apply { disableHwAttestation = true }

        /**
         * @see AndroidAttestationConfiguration.enableSoftwareAttestation
         */
        fun enableSoftwareAttestation() = apply { enableSwAttestation = true }

        /**
         * @see AndroidAttestationConfiguration.enableNougatAttestation
         */
        fun enableNougatAttestation() = apply { enableNougatAttestation = true }

        fun build() = AndroidAttestationConfiguration(
            applications = applications,
            androidVersion = androidVersion,
            patchLevel = patchLevel,
            requireStrongBox = requireStrongBox,
            bootloaderUnlockAllowed = bootloaderUnlockAllowed,
            requireRollbackResistance = rollbackResitanceRequired,
            ignoreLeafValidity = ignoreLeafValidity,
            hardwareAttestationTrustAnchors = hardwareAttestationTrustAnchors,
            softwareAttestationTrustAnchors = softwareAttestationTrustAnchors,
            verificationSecondsOffset = verificationSecondsOffset,
            disableHardwareAttestation = disableHwAttestation,
            enableSoftwareAttestation = enableSwAttestation,
            enableNougatAttestation = enableNougatAttestation
        )

    }
}