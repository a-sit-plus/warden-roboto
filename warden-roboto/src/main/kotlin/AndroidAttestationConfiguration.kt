package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AndroidAttestationException
import com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY
import io.ktor.util.*
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
 * Main Android attestation configuration class serving as ground truth for all key and app attestation verifications.
 *
 * @param applications list of applications to be attested
 * @param androidVersion optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
 * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
 * Can be overridden for individual apps
 * @param patchLevel optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter
 * @param requireStrongBox optional parameter. Set to `true` if *StrongBox* security level should be required
 * @param allowBootloaderUnlock optional parameter. Set to true if unlocked bootloaders should be allowed.
 * **Attention:** Allowing unlocked bootloaders in production effectively defeats the purpose of app attestation.
 * (but retains the ability to attest whether a key is securely stored in hardware)
 * Useful for debugging/testing
 * @param requireRollbackResistance optional parameter. Unsupported by most devices.
 * See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
 * @param ignoreLeafValidity optional parameter. Whether to ignore the timely validity of the leaf certificate (looking at you, Samsung!)
 * @param hardwareAttestationTrustAnchors Manually specify the trust anchor for HW-attested certificate chains.
 * Defaults to google HW attestation key. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
 * @param softwareAttestationTrustAnchors Manually specify the trust anchor for SW-attested certificate chains.
 * Defaults to google SW attestation keys. Overriding this set is useful for automated end-to-end tests, for example.
 * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
 * @param disableHardwareAttestation Entirely disable creation of a [HardwareAttestationChecker].
 * Only change this flag, if you **really** know what you are doing!
 * @param enableNougatAttestation Enables hybrid attestation.
 * [NougatHybridAttestationChecker] can only be instantiated if this flag is set to true.
 * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
 * devices only support hardware-backed key attestation, but provide no indication about the OS state.
 * Hence, app-attestation cannot be trusted, but key attestation still can.
 * @param enableSoftwareAttestation Enables software attestation.
 * A [SoftwareAttestationChecker] can only be instantiated if this flag is set to true.
 * Only change this flag, if you **really** know what you are doing!
 * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
 * [HardwareAttestationChecker] and a [SoftwareAttestationChecker].
 */
data class AndroidAttestationConfiguration @JvmOverloads constructor(

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
    internal val patchLevel: PatchLevel? = null,

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
    val allowBootloaderUnlock: Boolean = false,

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
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
     */
    val hardwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS),

    /**
     * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
     * Overriding this set is useful for automated end-to-end tests, for example.
     * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
     */
    val softwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS),

    /**
     *  Tolerance in seconds added to verification date
     */
    val verificationSecondsOffset: Int = 0,

    /**
     * Validity of the attestation statement in seconds. This is not the certificate validity!
     * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
     */
    val attestationStatementValiditySeconds: Int = 10 * 60,

    /**
     * Entirely disable creation of a [HardwareAttestationChecker]. Only change this flag, if you **really** know what
     * you are doing!
     * @see enableSoftwareAttestation
     */
    val disableHardwareAttestation: Boolean = false,

    /**
     * Enables hybrid attestation. A [NougatHybridAttestationChecker] can only be instantiated if this flag is set to true.
     * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
     * devices only support hardware-backed key attestation, but provide no indication about the OS state.
     * Hence, app-attestation cannot be trusted, but key attestation still can.
     */
    val enableNougatAttestation: Boolean = false,

    /**
     * Enables software attestation. A [SoftwareAttestationChecker] can only be instantiated if this flag is set to true.
     * Only change this flag, if you **really** know what you are doing!
     * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
     * [HardwareAttestationChecker] and a [SoftwareAttestationChecker].
     */
    val enableSoftwareAttestation: Boolean = false,

    /**
     * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
     */
    val httpProxy: String? = null

) {

    /**
     * Convenience constructor to attest a single app1
     */
    constructor(
        /**
         * The single application to be attested
         */
        singleApp: AppData,

        /**
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
         * Can be overridden for individual apps
         */
        androidVersion: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         * Can be overridden for individual apps.
         */
        patchLevel: PatchLevel? = null,

        /**
         * Set to `true` if *StrongBox* security level should be required.
         * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
         * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = false,

        /**
         * Manually specify the trust anchor for HW-attested certificate chains. Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [DEFAULT_HARDWARE_TRUST_ANCHORS]
         */
        hardwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_HARDWARE_TRUST_ANCHORS),

        /**
         * Manually specify the trust anchor for SW-attested certificate chains. Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are accessible through [DEFAULT_SOFTWARE_TRUST_ANCHORS]
         */
        softwareAttestationTrustAnchors: Set<PublicKey> = linkedSetOf(*DEFAULT_SOFTWARE_TRUST_ANCHORS),

        /**
         *  Tolerance in seconds added to verification date
         */
        verificationSecondsOffset: Int = 0,

        /**
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         */
        attestationStatementValiditySeconds: Int = 10 * 60,

        /**
         * Entirely disable creation of a [HardwareAttestationChecker]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */
        disableHardwareAttestation: Boolean = false,

        /**
         * Enables hybrid attestation. A [NougatHybridAttestationChecker] can only be instantiated if this flag is set to true.
         * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
         * devices only support hardware-backed key attestation, but provide no indication about the OS state.
         * Hence, app-attestation cannot be trusted, but key attestation still can.
         */
        enableNougatAttestation: Boolean = false,

        /**
         * Enables software attestation. A [SoftwareAttestationChecker] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [HardwareAttestationChecker] and a [SoftwareAttestationChecker].
         */
        enableSoftwareAttestation: Boolean = false,

        /**
         * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
         */
        httpProxy: String? = null
    ) : this(
        listOf(singleApp),
        androidVersion = androidVersion,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareAttestationTrustAnchors = hardwareAttestationTrustAnchors,
        softwareAttestationTrustAnchors = softwareAttestationTrustAnchors,
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableNougatAttestation = enableNougatAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        httpProxy = httpProxy
    )

    /**
     * Constructor used when loading this class from a config file through [Hoplite](https://github.com/sksamuel/hoplite)
     */
    constructor(
        /**
         * optional parameter. If set, attestation enforces Android version to be greater or equal to this parameter.
         * **Caution:** Major Android versions increment in steps of thousands. I.e. Android 11 is specified as `11000`
         * Can be overridden for individual apps
         */
        version: Int? = null,

        /**
         * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
         * Can be overridden for individual apps.
         */
        patchLevel: PatchLevel? = null,

        /**
         * Set to `true` if *StrongBox* security level should be required.
         * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
         */
        requireStrongBox: Boolean = false,

        /**
         * Set to true if unlocked bootloaders should be allowed. **Attention:** Allowing unlocked bootloaders in production
         * effectively defeats the purpose of Key Attestation. Useful for debugging/testing
         * **BEWARE** that this switch is utterly useless if [NougatHybridAttestationChecker] of [SoftwareAttestationChecker] is used
         */
        allowBootloaderUnlock: Boolean = false,

        /**
         * Unsupported by most devices. See [Official Documentation](https://source.android.com/docs/security/features/keystore/implementer-ref#rollback_resistance)
         */
        requireRollbackResistance: Boolean = false,

        /**
         * Whether to ignore the timely validity of the leaf certificate
         */
        ignoreLeafValidity: Boolean = false,


        /**
         *  Tolerance in seconds added to verification date
         */
        verificationSecondsOffset: Int = 0,

        /**
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         */
        attestationStatementValiditySeconds: Int = 10 * 60,

        /**
         * Entirely disable creation of a [HardwareAttestationChecker]. Only change this flag, if you **really** know what
         * you are doing!
         * @see enableSoftwareAttestation
         */

        disableHardwareAttestation: Boolean = false,

        /**
         * Enables hybrid attestation. A [NougatHybridAttestationChecker] can only be instantiated if this flag is set to true.
         * Only change this flag, if you require support for devices, which originally shipped with Android 7 (Nougat), as these
         * devices only support hardware-backed key attestation, but provide no indication about the OS state.
         * Hence, app-attestation cannot be trusted, but key attestation still can.
         */
        enableNougatAttestation: Boolean = false,

        /**
         * Enables software attestation. A [SoftwareAttestationChecker] can only be instantiated if this flag is set to true.
         * Only change this flag, if you **really** know what you are doing!
         * Enabling this flag, while keeping [disableHardwareAttestation] `true` makes is possible to instantiate both a
         * [HardwareAttestationChecker] and a [SoftwareAttestationChecker].
         */
        enableSoftwareAttestation: Boolean = false,


        /**
         * Manually specify the trust anchors for HW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google HW attestation key.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchor is accessible through [GOOGLE_ROOT_CA_PUB_KEY].
         */
        hardwareAttestationRootKeys: Set<ByteArray> = DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.encoded }.toSet(),

        /**
         * Manually specify the trust anchor for SW-attested certificate chains as X.509-encoded public keys.
         * The reason for this format in the default constructor is to make file-based configuration through [Hoplite](https://github.com/sksamuel/hoplite) a breeze.
         * Defaults to google SW attestation keys.
         * Overriding this set is useful for automated end-to-end tests, for example.
         * The default trust anchors are [GOOGLE_SOFTWARE_EC_ROOT], [GOOGLE_SOFTWARE_RSA_ROOT]
         */
        softwareAttestationRootKeys: Set<ByteArray> = DEFAULT_SOFTWARE_TRUST_ANCHORS.map { it.encoded }.toSet(),

        /**
         * List of applications, which can be attested
         */
        apps: List<AppData>,

        /**
         * HTTP Proxy URL formatted as `http(s)://proxy-domain:port`
         */
        httpProxy: String? = null
    ) : this(
        applications = apps,
        androidVersion = version,
        patchLevel = patchLevel,
        requireStrongBox = requireStrongBox,
        allowBootloaderUnlock = allowBootloaderUnlock,
        requireRollbackResistance = requireRollbackResistance,
        ignoreLeafValidity = ignoreLeafValidity,
        hardwareAttestationTrustAnchors = hardwareAttestationRootKeys.map { it.parsePublicKey() }.toSet(),
        softwareAttestationTrustAnchors = softwareAttestationRootKeys.map { it.parsePublicKey() }.toSet(),
        verificationSecondsOffset = verificationSecondsOffset,
        attestationStatementValiditySeconds = attestationStatementValiditySeconds,
        disableHardwareAttestation = disableHardwareAttestation,
        enableNougatAttestation = enableNougatAttestation,
        enableSoftwareAttestation = enableSoftwareAttestation,
        httpProxy = httpProxy,
    )

    /**
     * Internal representation of the patch level as contained in the [com.google.android.attestation.ParsedAttestationRecord]
     */
    val osPatchLevel: Int? = patchLevel?.asSingleInt

    /**
     * Specifies a to-be attested app
     *
     * @param packageName Android app package name (e.g. `at.asitplus.demo`)
     * @param signatureDigests SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing
     * certificate for production play store releases. Being able to specify multiple digests makes it easy to use development
     * builds and production builds in parallel.
     * @param appVersion optional parameter. If set, attestation enforces application version to be greater or equal to this parameter
     * */
    data class AppData @JvmOverloads constructor(
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
        internal val patchLevelOverride: PatchLevel? = null,

        ) {
        init {
            if (signatureDigests.isEmpty()) throw object :
                AndroidAttestationException("No signature digests specified", null) {}
        }

        /**
         * Internal representation of the patch level as previously contained in the [com.google.android.attestation.ParsedAttestationRecord]
         */
        val osPatchLevel: Int? = patchLevelOverride?.asSingleInt

        /**
         * Builder for more java-friendliness
         * @param packageName Android app package name (e.g. `at.asitplus.demo`)
         * @param signatureDigests  SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
         * production play store releases.
         * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
         */
        class Builder(private val packageName: String, private val signatureDigests: List<ByteArray>) {

            /**
             * Builder for more java-friendliness
             * @param packageName Android app package name (e.g. `at.asitplus.demo`)
             * @param signatureDigests  SHA-256 digests of signature certificates used to sign the APK. This is a Google cloud signing certificate for
             * production play store releases.
             * Being able to specify multiple digests makes it easy to use development builds and production builds in parallel
             */
            constructor(packageName: String, vararg signatureDigests: ByteArray) : this(
                packageName,
                signatureDigests.asList()
            )

            private var appVersion: Int? = null
            private var androidVersionOverride: Int? = null
            private var patchLevelOverride: PatchLevel? = null

            /**
             * @see AppData.appVersion
             */
            fun appVersion(version: Int) = apply { appVersion = version }

            /**
             * @see AppData.androidVersionOverride
             */
            fun overrideAndroidVersion(version: Int) = apply { androidVersionOverride = version }

            /**
             * optional parameter. If set, attestation enforces Security patch level to be greater or equal to this parameter.
             */
            fun overridePatchLevel(level: PatchLevel) = apply { patchLevelOverride = level }

            fun build() =
                AppData(packageName, signatureDigests, appVersion, androidVersionOverride, patchLevelOverride)
        }

    }

    init {
        if (hardwareAttestationTrustAnchors.isEmpty() && softwareAttestationTrustAnchors.isEmpty())
            throw object : AndroidAttestationException("No trust anchors configured", null) {}

        if (applications.isEmpty()) throw object : AndroidAttestationException("No apps configured", null) {}
        if (disableHardwareAttestation && !enableSoftwareAttestation && !enableNougatAttestation)
            throw object : AndroidAttestationException(
                "Neither hardware, nor hybrid, nor software attestation enabled", null
            ) {}
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

        private var attestationStatementValiditySeconds = 10 * 60

        private var disableHwAttestation: Boolean = false
        private var enableSwAttestation: Boolean = false
        private var enableNougatAttestation: Boolean = false
        private var httpProxy: String? = null

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
         * @see AndroidAttestationConfiguration.allowBootloaderUnlock
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
        fun addHardwareAttestationTrustAnchor(anchor: PublicKey) = apply { hardwareAttestationTrustAnchors += anchor }

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
         * Validity of the attestation statement in seconds. This is not the certificate validity!
         * An attestation statement has a creation time. This value indicates how far in the past the creation time might be.
         */
        fun attestationStatementValiditySeconds(seconds: Int) = apply { attestationStatementValiditySeconds = seconds }

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

        /**
         * @see AndroidAttestationConfiguration.httpProxy
         */
        fun httpProxy(url: String) = apply { httpProxy = url }

        fun build() = AndroidAttestationConfiguration(
            applications = applications,
            androidVersion = androidVersion,
            patchLevel = patchLevel,
            requireStrongBox = requireStrongBox,
            allowBootloaderUnlock = bootloaderUnlockAllowed,
            requireRollbackResistance = rollbackResitanceRequired,
            ignoreLeafValidity = ignoreLeafValidity,
            hardwareAttestationTrustAnchors = hardwareAttestationTrustAnchors,
            softwareAttestationTrustAnchors = softwareAttestationTrustAnchors,
            verificationSecondsOffset = verificationSecondsOffset,
            attestationStatementValiditySeconds = attestationStatementValiditySeconds,
            disableHardwareAttestation = disableHwAttestation,
            enableSoftwareAttestation = enableSwAttestation,
            enableNougatAttestation = enableNougatAttestation,
            httpProxy = httpProxy,
        )

    }
}

private fun ByteArray.parsePublicKey() =
    runCatching {
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(this))
    }.getOrElse {
        runCatching {
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(this))
        }.getOrElse {
            throw object : AndroidAttestationException("Not a valid public key: ${this.encodeBase64()}", null) {}
        }
    }