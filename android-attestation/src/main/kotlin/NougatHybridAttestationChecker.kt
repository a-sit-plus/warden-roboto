package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException
import com.google.android.attestation.ParsedAttestationRecord
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.cache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import java.util.*

class NougatHybridAttestationChecker @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : AndroidAttestationChecker(attestationConfiguration, verifyChallenge) {

    init {
        if (!attestationConfiguration.enableNougatAttestation) throw AttestationException("Hardware attestation is disabled!")
        if (attestationConfiguration.hardwareAttestationTrustAnchors.isEmpty()) throw AttestationException("No hardware attestation trust anchors configured")
    }

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel() {
        if (attestationConfiguration.requireStrongBox) {
            if (keymasterSecurityLevel != ParsedAttestationRecord.SecurityLevel.STRONG_BOX)
                throw AttestationException("Keymaster security level not StrongBox")
        } else {
            if (keymasterSecurityLevel == ParsedAttestationRecord.SecurityLevel.SOFTWARE)
                throw AttestationException("Keymaster security level software")
        }
        if (attestationSecurityLevel != ParsedAttestationRecord.SecurityLevel.SOFTWARE) {
            throw AttestationException("Attestation security level not software")
        }
    }

    override val trustAnchors = attestationConfiguration.softwareAttestationTrustAnchors

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyAndroidVersion(versionOverride: Int?, osPatchLevel: Int?) {
        //impossible
    }

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() {
        //impossible
    }

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyRollbackResistance() = teeEnforced.verifyRollbackResistance()
}