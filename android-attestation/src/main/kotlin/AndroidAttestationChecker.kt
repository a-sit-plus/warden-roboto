package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
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
import java.security.cert.X509Certificate
import java.util.*

abstract class AndroidAttestationChecker(
    protected val attestationConfiguration: AndroidAttestationConfiguration,
    private val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean
) {

    @Throws(CertificateInvalidException::class, RevocationException::class)
    private fun List<X509Certificate>.verifyCertificateChain(verificationDate: Date) {

        runCatching { verifyRootCertificate(verificationDate) }
            .onFailure { throw CertificateInvalidException("could not verify root certificate", cause = it) }
        val revocationStatusList = runCatching { RevocationList.fromGoogleServer() }
            .getOrElse { throw RevocationException("could not download revocation information", it) }
        let {
            if (attestationConfiguration.ignoreLeafValidity) mapIndexed { i, cert ->
                if (i == 0) EternalX509Certificate(cert) else cert
            } else it
        }.reversed().zipWithNext { parent, certificate ->
            verifyCertificatePair(certificate, parent, verificationDate, revocationStatusList)
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
            throw CertificateInvalidException(it.message ?: "Certificate invalid", it)
        }
        runCatching {
            statusList.isRevoked(certificate.serialNumber)
        }.onSuccess {
            if (it) // getting any status means not trustworthy
                throw RevocationException("Certificate revoked")
        }.onFailure {
            throw RevocationException("Could not get revocation list", it)
        }
    }

    private fun List<X509Certificate>.verifyRootCertificate(verificationDate: Date) {
        val root = last()
        root.checkValidity(verificationDate)
        val matchingTrustAnchor = trustAnchors
            .firstOrNull { root.publicKey.encoded.contentEquals(it.encoded) }
            ?: throw CertificateInvalidException("No matching root certificate")
        root.verify(matchingTrustAnchor)
    }

    protected abstract val trustAnchors: Collection<PublicKey>

    @Throws(AttestationException::class)
    private fun ParsedAttestationRecord.verifyApplication(application: AndroidAttestationConfiguration.AppData) {
        runCatching {
            if (softwareEnforced.attestationApplicationId.get().packageInfos.first().packageName != application.packageName) {
                throw AttestationException("Invalid Application Package")
            }
            application.appVersion?.let { configuredVersion ->
                if (softwareEnforced.attestationApplicationId.get().packageInfos.first().version < configuredVersion) {
                    throw AttestationException("Application Version not supported")
                }
            }

            if (!softwareEnforced.attestationApplicationId.get().signatureDigests.any { fromAttestation ->
                    application.signatureDigests.any { it.contentEquals(fromAttestation) }
                }) {
                throw AttestationException("Invalid Application Signature Digest")
            }
        }.onFailure {
            throw when (it) {
                is AttestationException -> it
                else -> AttestationException("Could not verify Client Application", it)
            }
        }
    }


    @Throws(AttestationException::class)
    protected abstract fun ParsedAttestationRecord.verifyAndroidVersion(
        versionOverride: Int? = null,
        osPatchLevel: Int?
    )
    protected fun AuthorizationList.verifyAndroidVersion(versionOverride: Int?, patchLevel: Int?) {
        runCatching {

           (versionOverride?: attestationConfiguration.androidVersion)?.let {
                if ((osVersion.get()) < it) throw AttestationException("Android version not supported")
            }

            (patchLevel?:attestationConfiguration.osPatchLevel)?.let {
                if ((osPatchLevel.get()) < it) throw AttestationException("Patch level not supported")
            }
        }.onFailure {
            throw when (it) {
                is AttestationException -> it
                else -> AttestationException("Could not verify Android Version", it)
            }
        }
    }


    @Throws(AttestationException::class)
    protected abstract fun ParsedAttestationRecord.verifyBootStateAndSystemImage()

    @Throws(AttestationException::class)
    protected fun AuthorizationList.verifySystemLocked() {
        if (attestationConfiguration.bootloaderUnlockAllowed) return

        if (rootOfTrust == null) throw AttestationException("Root of Trust not present")

        if (!rootOfTrust.get().deviceLocked) throw AttestationException("Bootloader not locked")

        if ((rootOfTrust.get().verifiedBootState
                ?: RootOfTrust.VerifiedBootState.FAILED) != RootOfTrust.VerifiedBootState.VERIFIED
        ) throw AttestationException("System image not verified")
    }

    @Throws(AttestationException::class)
    protected abstract fun ParsedAttestationRecord.verifyRollbackResistance()

    @Throws(AttestationException::class)
    protected fun AuthorizationList.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!rollbackResistant) throw AttestationException("No rollback resistance")
    }

    /**
     * Verifies Android Key attestation Implements in accordance with https://developer.android.com/training/articles/security-key-attestation.
     * Checks are performed according to the properties set in the [attestationConfiguration].
     *
     * @See [AndroidAttestationConfiguration] for details on what is and is not checked.
     *
     * @return [ParsedAttestationRecord] on success
     * @throws AttestationException if a property fails to verify according to the current configuration
     * @throws RevocationException if a certificate has been revoked
     * @throws CertificateInvalidException if certificates fail to verify
     *
     */
    @Throws(AttestationException::class, CertificateInvalidException::class, RevocationException::class)
    open fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord {
        val calendar = Calendar.getInstance()
        calendar.time = verificationDate
        calendar.add(Calendar.SECOND, attestationConfiguration.verificationSecondsOffset)
        certificates.verifyCertificateChain(calendar.time)

        val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates)
        if (!verifyChallenge(
                expectedChallenge,
                parsedAttestationRecord.attestationChallenge
            )
        ) throw AttestationException("verification of attestation challenge failed")

        parsedAttestationRecord.verifySecurityLevel()
        parsedAttestationRecord.verifyBootStateAndSystemImage()
        parsedAttestationRecord.verifyRollbackResistance()

        val attestedApp = attestationConfiguration.applications.associateWith { app ->
            runCatching { parsedAttestationRecord.verifyApplication(app) }
        }.let {
            it.entries.firstOrNull { (_, result) -> result.isSuccess } ?: it.values.first().exceptionOrNull()!!.let { throw it }
        }.key
        parsedAttestationRecord.verifyAndroidVersion(attestedApp.androidVersionOverride, attestedApp.osPatchLevel)
        return parsedAttestationRecord
    }

    @Throws(AttestationException::class)
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
            private val client by lazy { CIO.create().setup() }

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

private val json = Json { ignoreUnknownKeys = true }


fun HttpClientEngine.setup() =
    HttpClient(this) {
        install(HttpCache)
        install(ContentNegotiation) {
            json(json)
        }
    }