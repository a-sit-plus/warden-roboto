package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import at.asitplus.catchingUnwrapped
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath
import com.android.keyattestation.verifier.provider.KeyAttestationProvider
import com.google.android.attestation.AuthorizationList
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.Security
import java.security.cert.*
import java.time.Duration
import java.time.Instant
import java.time.YearMonth
import java.util.*
import kotlin.jvm.optionals.getOrNull

abstract class AndroidAttestationChecker(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    private val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {
    companion object {
        init {
            Security.addProvider(KeyAttestationProvider())
        }

        private fun getValidator() = CertPathValidator.getInstance("KeyAttestation")
    }

    private val newPkixCertPathValidator = getValidator()

    private val revocationListClient = HttpClient(CIO) { setup(attestationConfiguration.httpProxy) }

    @Throws(CertificateInvalidException::class, RevocationException::class)
    private fun List<X509Certificate>.verifyCertificateChain(verificationDate: Date) {

        runCatching { verifyRootCertificate(verificationDate) }
            .onFailure {
                throw if (it is CertificateInvalidException) it else CertificateInvalidException(
                    "could not verify root certificate (valid from: ${last().notBefore} to ${last().notAfter}), verification date: $verificationDate",
                    cause = it,
                    if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST
                )
            }
        val revocationStatusList = runCatching { RevocationList.fromGoogleServer(client = revocationListClient) }
            .getOrElse {
                throw RevocationException(
                    "could not download revocation information",
                    it,
                    RevocationException.Reason.LIST_UNAVAILABLE
                )
            }
        val certificateChain =
            if (attestationConfiguration.ignoreLeafValidity) mapIndexed { i, cert ->
                if (i == 0) EternalX509Certificate(cert) else cert
            } else this

        certificateChain.reversed().zipWithNext { parent, certificate ->
            verifyCertificatePair(certificate, parent, verificationDate, revocationStatusList)
        }

        //now we double-check against the new validator to rule out manipulations of the certificate chain
        catchingUnwrapped {
            newPkixCertPathValidator.validate(
                KeyAttestationCertPath(certificateChain),
                PKIXParameters(
                    setOf(TrustAnchor(certificateChain.last(), null))
                ).apply {
                    date = verificationDate
                    isRevocationEnabled =
                        false //we check manually as per the official documentation, and we've done that already
                }
            )
        }.onFailure {
            throw CertificateInvalidException(
                it.message ?: "Invalid certificate chain",
                it,
                CertificateInvalidException.Reason.TRUST //we have ruled out time beforehand
            )
        }

    }

    @Throws(RevocationException::class, CertificateInvalidException::class)
    private fun verifyCertificatePair(
        certificate: X509Certificate,
        parent: X509Certificate,
        verificationDate: Date,
        statusList: RevocationList
    ) {
        runCatching {
            certificate.checkValidity(verificationDate)
            certificate.verify(parent.publicKey)
        }.onFailure {
            throw CertificateInvalidException(
                it.message ?: "Certificate invalid",
                it,
                if ((it is CertificateExpiredException) || (it is CertificateNotYetValidException)) CertificateInvalidException.Reason.TIME else CertificateInvalidException.Reason.TRUST
            )
        }
        runCatching {
            statusList.isRevoked(certificate.serialNumber)
        }.onSuccess {
            if (it)
                throw RevocationException("Certificate revoked", reason = RevocationException.Reason.REVOKED)
        }.onFailure {
            throw RevocationException(
                "Could not init revocation list",
                it,
                RevocationException.Reason.LIST_UNAVAILABLE
            )
        }
    }

    private fun List<X509Certificate>.verifyRootCertificate(verificationDate: Date) {
        val root = last()
        root.checkValidity(verificationDate)
        val matchingTrustAnchor = trustAnchors
            .firstOrNull { root.publicKey.encoded.contentEquals(it.encoded) }
            ?: run {
                val additionalInfo =
                    if (DEFAULT_HARDWARE_TRUST_ANCHORS.map { it.encoded }
                            .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null) ". Found a default HARDWARE Root"
                    else if (DEFAULT_SOFTWARE_TRUST_ANCHORS.map { it.encoded }
                            .firstOrNull { it.contentEquals(root.publicKey.encoded) } != null) ". Found a default SOFTWARE Root"
                    else ". Found: ${root.encoded.encodeBase64()}"

                root.publicKey.encoded
                throw CertificateInvalidException(
                    "No matching root certificate$additionalInfo",
                    reason = CertificateInvalidException.Reason.TRUST
                )
            }
        root.verify(matchingTrustAnchor)
    }

    protected abstract val trustAnchors: Collection<PublicKey>

    protected open fun ParsedAttestationRecord.verifyAttestationTime(verificationDate: Instant) {
        if (attestationConfiguration.attestationStatementValiditySeconds == null) return //no validity, no checks!
        val createdAt =
            teeEnforced().creationDateTime().getOrNull() ?: softwareEnforced().creationDateTime().getOrNull()
        if (createdAt == null) throw AttestationValueException(
            "Attestation statement creation time missing",
            reason = AttestationValueException.Reason.TIME
        )
        var checkTime = verificationDate.plusSeconds(attestationConfiguration.verificationSecondsOffset.toLong())
        val difference = Duration.between(createdAt, checkTime)
        if (difference.isNegative) throw AttestationValueException(
            "Attestation statement creation time too far in the future: $createdAt, check time: $checkTime",
            reason = AttestationValueException.Reason.TIME
        )

        if (difference > Duration.ofSeconds(attestationConfiguration.attestationStatementValiditySeconds.toLong())) throw AttestationValueException(
            "Attestation statement creation time too far in the past: $createdAt, check time: $checkTime, attestation statement validity in seconds: ${attestationConfiguration.attestationStatementValiditySeconds}",
            reason = AttestationValueException.Reason.TIME
        )


    }

    @Throws(AttestationValueException::class)
    private fun ParsedAttestationRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        runCatching {
            if (!(softwareEnforced().attestationApplicationId().get().packageInfos().any {
                    it.packageName() == application.packageName
                })
            ) {
                throw AttestationValueException(
                    "Invalid Application Package: ${
                        softwareEnforced().attestationApplicationId().get().packageInfos()
                            .joinToString { it.packageName() }
                    } (should be: ${application.packageName})",
                    reason = AttestationValueException.Reason.PACKAGE_NAME
                )
            }
            application.appVersion?.let { configuredVersion ->
                if (softwareEnforced().attestationApplicationId().get().packageInfos().first()
                        .version() < configuredVersion
                ) {
                    throw AttestationValueException(
                        "Application Version not supported",
                        reason = AttestationValueException.Reason.APP_VERSION
                    )
                }
            }

            if (!softwareEnforced().attestationApplicationId().get().signatureDigests().any { fromAttestation ->
                    application.signatureDigests.any { it.contentEquals(fromAttestation.toByteArray()) }
                }) {
                throw AttestationValueException(
                    "Invalid Application Signature Digest",
                    reason = AttestationValueException.Reason.APP_SIGNER_DIGEST
                )
            }
        }.onFailure {
            throw when (it) {
                is AttestationValueException -> it
                else -> AttestationValueException(
                    "Could not verify Client Application",
                    it,
                    reason = AttestationValueException.Reason.APP_UNEXPECTED
                )
            }
        }
    }


    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifyAndroidVersion(
        versionOverride: Int? = null,
        osPatchLevel: PatchLevel?
    )

    protected fun AuthorizationList.verifyAndroidVersion(versionOverride: Int?, patchLevel: PatchLevel?) {
        runCatching {

            (versionOverride ?: attestationConfiguration.androidVersion)?.let {
                if ((osVersion().get()) < it) throw AttestationValueException(
                    "Android version not supported: ${osVersion().get()} (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION
                )
            }

            (patchLevel ?: attestationConfiguration.patchLevel)?.let {
                if ((osPatchLevel().get()).isBefore(YearMonth.of(it.year, it.month))) throw AttestationValueException(
                    "Patch level not supported: ${osPatchLevel().get()} (should be at least $it)",
                    reason = AttestationValueException.Reason.OS_VERSION
                )
            }
        }.onFailure {
            throw when (it) {
                is AttestationValueException -> it
                else -> AttestationValueException(
                    "Could not verify Android Version",
                    it,
                    AttestationValueException.Reason.OS_VERSION
                )
            }
        }
    }


    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifyBootStateAndSystemImage()

    @Throws(AttestationValueException::class)
    protected fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.allowBootloaderUnlock) return

        if (rootOfTrust() == null) throw AttestationValueException(
            "Root of Trust not present",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY
        )

        if (!rootOfTrust().get().deviceLocked()) throw AttestationValueException(
            "Bootloader not locked",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY
        )

        if ((rootOfTrust().get().verifiedBootState()
                ?: RootOfTrust.VerifiedBootState.FAILED) != RootOfTrust.VerifiedBootState.VERIFIED
        ) throw AttestationValueException(
            "System image not verified",
            reason = AttestationValueException.Reason.SYSTEM_INTEGRITY
        )
    }

    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifyRollbackResistance()

    @Throws(AttestationValueException::class)
    protected fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!rollbackResistance()) throw AttestationValueException(
                "No rollback resistance",
                reason = AttestationValueException.Reason.ROLLBACK_RESISTANCE
            )
    }

    /**
     * Packs
     * * the current configuration
     * * the passed attestation proof
     * * the passed date
     *
     * into a serializable data structure for easy debugging
     */
    fun collectDebugInfo(
        certificates: List<X509Certificate>,
        expectedChallenge: ByteArray,
        verificationDate: Date = Date(),
    ) = AndroidDebugAttestationStatement(
        this,
        attestationConfiguration,
        verificationDate,
        expectedChallenge,
        certificates
    )

    /**
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     * @return [ParsedAttestationRecord] on success
     * @throws AttestationValueException if a property fails to verify according to the current configuration
     * @throws RevocationException if a certificate has been revoked
     * @throws CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationValueException::class, CertificateInvalidException::class, RevocationException::class)
    open fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord {
        val actualVerificationDate =
            Date.from(verificationDate.toInstant().plusSeconds(attestationConfiguration.verificationSecondsOffset))
        certificates.verifyCertificateChain(actualVerificationDate)

        val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates)
        if (!verifyChallenge(
                expectedChallenge,
                parsedAttestationRecord.attestationChallenge().toByteArray()
            )
        ) throw AttestationValueException(
            "verification of attestation challenge failed",
            reason = AttestationValueException.Reason.CHALLENGE
        )
        parsedAttestationRecord.verifyAttestationTime(verificationDate.toInstant())
        parsedAttestationRecord.verifySecurityLevel()
        parsedAttestationRecord.verifyBootStateAndSystemImage()
        parsedAttestationRecord.verifyRollbackResistance()

        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            runCatching { parsedAttestationRecord.verifyApplication(app) }
        }.let {
            it.entries.firstOrNull { (_, result) -> result.isSuccess } ?: it.values.first().exceptionOrNull()!!
                .let { throw it }
        }.key
        parsedAttestationRecord.verifyAndroidVersion(attestedApp.androidVersionOverride, attestedApp.patchLevelOverride)
        return parsedAttestationRecord
    }

    @Throws(AttestationValueException::class)
    protected abstract fun ParsedAttestationRecord.verifySecurityLevel()

    /**
     * taken and adapted from [com.google.android.attestation.CertificateRevocationStatus] to separate downloading and checking
     */
    class RevocationList(json: JsonObject) {
        private val entries by lazy { json["entries"]?.jsonObject ?: throw IOException() }
        fun isRevoked(
            serialNumber: BigInteger
        ): Boolean {
            val serialNumberNormalised = serialNumber.toString(16).lowercase(Locale.getDefault())
            return entries[serialNumberNormalised] != null //any entry is a red flag!
        }

        companion object {
            @JvmStatic
            private val client by lazy { HttpClient(CIO) { setup(null) } }

            @OptIn(ExperimentalSerializationApi::class)
            @JvmStatic
            fun from(source: InputStream) = RevocationList(json.decodeFromStream(source))

            @Throws(Throwable::class)
            @JvmStatic
            @JvmOverloads
            fun fromGoogleServer(client: HttpClient = this.client) =
                runBlocking {
                    RevocationList(client.get("https://android.googleapis.com/attestation/status").body<JsonObject>())
                }
        }
    }
}


class EternalX509Certificate(private val delegate: X509Certificate) : X509Certificate() {
    override fun toString() = delegate.toString()

    override fun getEncoded(): ByteArray = delegate.encoded

    override fun verify(key: PublicKey?) = delegate.verify(key)

    override fun verify(key: PublicKey?, sigProvider: String?) = delegate.verify(key, sigProvider)

    override fun getPublicKey(): PublicKey = delegate.publicKey

    override fun hasUnsupportedCriticalExtension(): Boolean = delegate.hasUnsupportedCriticalExtension()

    override fun getCriticalExtensionOIDs(): MutableSet<String> = delegate.criticalExtensionOIDs

    override fun getNonCriticalExtensionOIDs(): MutableSet<String> = delegate.nonCriticalExtensionOIDs

    override fun getExtensionValue(oid: String?): ByteArray = delegate.getExtensionValue(oid)

    override fun checkValidity() {
        /*NOOP*/
    }

    override fun checkValidity(date: Date?) {
        /*NOOP*/
    }

    override fun getVersion(): Int = delegate.version

    override fun getSerialNumber(): BigInteger = delegate.serialNumber

    override fun getIssuerDN(): Principal = delegate.issuerDN

    override fun getSubjectDN(): Principal = delegate.subjectDN

    override fun getNotBefore(): Date = delegate.notBefore

    override fun getNotAfter(): Date = delegate.notAfter

    override fun getTBSCertificate(): ByteArray = delegate.tbsCertificate

    override fun getSignature(): ByteArray = delegate.signature

    override fun getSigAlgName(): String = delegate.sigAlgName

    override fun getSigAlgOID(): String = delegate.sigAlgOID

    override fun getSigAlgParams(): ByteArray = delegate.sigAlgParams

    override fun getIssuerUniqueID(): BooleanArray = delegate.issuerUniqueID

    override fun getSubjectUniqueID(): BooleanArray = delegate.subjectUniqueID

    override fun getKeyUsage(): BooleanArray = delegate.keyUsage

    override fun getBasicConstraints(): Int = delegate.basicConstraints

}

internal val json = Json { ignoreUnknownKeys = true }

fun HttpClientConfig<*>.setup(proxyUrl: String?) =
    apply {
        install(HttpCache)
        install(ContentNegotiation) { json(json) }
        engine { proxyUrl?.let { proxy = ProxyBuilder.http(it) } }
    }
