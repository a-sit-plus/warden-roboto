package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.android.exceptions.RevocationException
import com.google.android.attestation.CertificateRevocationStatus
import com.google.android.attestation.ParsedAttestationRecord
import com.google.android.attestation.RootOfTrust
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.Reader
import java.math.BigInteger
import java.net.URL
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.*

class AndroidAttestationChecker @JvmOverloads constructor(
    private val attestationConfiguration: AndroidAttestationConfiguration,
    private val verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
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
            statusList[certificate.serialNumber]
        }.onSuccess {
            if (it != null) // getting any status means not trustworthy
                throw RevocationException("Certificate revoked")
        }.onFailure {
            throw RevocationException("Could not get revocation list", it)
        }
    }

    private fun List<X509Certificate>.verifyRootCertificate(verificationDate: Date) {
        val root = last()
        root.checkValidity(verificationDate)
        val matchingTrustAnchor = attestationConfiguration.trustAnchors
            .firstOrNull { root.publicKey.encoded.contentEquals(it.encoded) }
            ?: throw CertificateInvalidException("No matching root certificate")
        root.verify(matchingTrustAnchor)
    }

    @Throws(AttestationException::class)
    private fun ParsedAttestationRecord.verifyApplicationPackageNameAndSignatureDigest() {
        runCatching {
            if (softwareEnforced.attestationApplicationId.get().packageInfos.first().packageName != attestationConfiguration.packageName) {
                throw AttestationException("Invalid Application Package")
            }
            attestationConfiguration.appVersion?.let { configuredVersion ->
                if (softwareEnforced.attestationApplicationId.get().packageInfos.first().version < configuredVersion) {
                    throw AttestationException("Application Version not supported")
                }
            }

            if (!softwareEnforced.attestationApplicationId.get().signatureDigests.any { fromAttestation ->
                    attestationConfiguration.signatureDigests.any { it.contentEquals(fromAttestation) }
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
    private fun ParsedAttestationRecord.verifyAndroidVersion() {
        runCatching {

            attestationConfiguration.androidVersion?.let {
                if ((teeEnforced.osVersion.get()) < it) throw AttestationException("Android version not supported")
            }

            attestationConfiguration.osPatchLevel?.let {
                if ((teeEnforced.osPatchLevel.get()) < it) throw AttestationException("Patch level not supported")
            }
        }.onFailure {
            throw when (it) {
                is AttestationException -> it
                else -> AttestationException("Could not verify Android Version", it)
            }
        }
    }

    @Throws(AttestationException::class)
    private fun ParsedAttestationRecord.verifyTeeEnforcedAttestation() {

        if (attestationConfiguration.requireStrongBox) {
            if (attestationSecurityLevel != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                throw AttestationException("Attestation security level not StrongBox")
            if (keymasterSecurityLevel != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                throw AttestationException("Keymaster security level not StrongBox")
        } else {
            if (attestationSecurityLevel == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                throw AttestationException("Attestation security level software")
            if (keymasterSecurityLevel == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                throw AttestationException("Keymaster security level software")
        }

    }

    @Throws(AttestationException::class)
    private fun ParsedAttestationRecord.verifyBootStateAndSystemImage() {
        if (attestationConfiguration.bootloaderUnlockAllowed) return

        if (teeEnforced.rootOfTrust == null) throw AttestationException("Root of Trust not present")

        if (!teeEnforced.rootOfTrust.get().deviceLocked) throw AttestationException("Bootloader not locked")

        if ((teeEnforced.rootOfTrust.get().verifiedBootState
                ?: RootOfTrust.VerifiedBootState.FAILED) != RootOfTrust.VerifiedBootState.VERIFIED
        ) throw AttestationException("System image not verified")

    }

    @Throws(AttestationException::class)
    private fun ParsedAttestationRecord.verifyRollbackResistance() {
        if (attestationConfiguration.requireRollbackResistance)
            if (!teeEnforced.rollbackResistant) throw AttestationException("No rollback resistance")
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
    fun verifyAttestation(
        certificates: List<X509Certificate>,
        verificationDate: Date = Date(),
        expectedChallenge: ByteArray
    ): ParsedAttestationRecord {
        certificates.verifyCertificateChain(verificationDate)

        val parsedAttestationRecord = ParsedAttestationRecord.createParsedAttestationRecord(certificates)
        if (!verifyChallenge(
                expectedChallenge,
                parsedAttestationRecord.attestationChallenge
            )
        ) throw AttestationException("verification of attestation challenge failed")

        parsedAttestationRecord.verifyTeeEnforcedAttestation()
        parsedAttestationRecord.verifyBootStateAndSystemImage()
        parsedAttestationRecord.verifyRollbackResistance()
        parsedAttestationRecord.verifyAndroidVersion()
        parsedAttestationRecord.verifyApplicationPackageNameAndSignatureDigest()
        return parsedAttestationRecord
    }

    /**
     * taken and adapted from [com.google.android.attestation.CertificateRevocationStatus] to separate downloading and checking
     */
    class RevocationList(json: JsonObject) {
        private val entries by lazy { json.getAsJsonObject("entries") }
        operator fun get(
            serialNumber: BigInteger
        ): CertificateRevocationStatus? {
            val serialNumberNormalised = serialNumber.toString(16).lowercase(Locale.getDefault())

            return if (!entries.has(serialNumberNormalised)) {
                null
            } else Gson().fromJson(entries[serialNumberNormalised], CertificateRevocationStatus::class.java)
        }

        companion object {
            fun from(source: Reader) = RevocationList(JsonParser.parseReader(source).asJsonObject)

            @Throws(Throwable::class)
            fun fromGoogleServer() = from(
                URL("https://android.googleapis.com/attestation/status").openStream().reader()
            )
        }
    }
}


class EternalX509Certificate(private val delegate: X509Certificate) : X509Certificate() {
    override fun toString() = delegate.toString()

    override fun getEncoded() = delegate.encoded

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

