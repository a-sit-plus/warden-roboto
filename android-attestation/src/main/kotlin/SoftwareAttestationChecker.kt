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
import java.security.PublicKey
import java.util.*

class SoftwareAttestationChecker @JvmOverloads constructor(
    attestationConfiguration: AndroidAttestationConfiguration,
    verifyChallenge: (expected: ByteArray, actual: ByteArray) -> Boolean = { expected, actual -> expected contentEquals actual }
) : AndroidAttestationChecker(attestationConfiguration, verifyChallenge) {
    init {
        if (attestationConfiguration.softwareAttestationTrustAnchors.isEmpty()) throw AttestationException("No software attestation trust anchors configured")
    }

    companion object {
        const val GOOGLE_SOFTWARE_EC_ROOT =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
                    "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA=="
        const val GOOGLE_SOFTWARE_RSA_ROOT =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf" +
                    "d5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg" +
                    "MdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm" +
                    "+Vfkl5YLCazOkjWFmwIDAQAB"
    }

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifySecurityLevel() {
        if (attestationSecurityLevel != ParsedAttestationRecord.SecurityLevel.SOFTWARE)
            throw AttestationException("Attestation security level not software")
        if (keymasterSecurityLevel != ParsedAttestationRecord.SecurityLevel.SOFTWARE)
            throw AttestationException("Keymaster security level not software")
    }

    override val trustAnchors: Collection<PublicKey> = attestationConfiguration.softwareAttestationTrustAnchors

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyAndroidVersion() = softwareEnforced.verifyAndroidVersion()

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyBootStateAndSystemImage() = softwareEnforced.verifySystemLocked()

    @Throws(AttestationException::class)
    override fun ParsedAttestationRecord.verifyRollbackResistance() = softwareEnforced.verifyRollbackResistance()
}