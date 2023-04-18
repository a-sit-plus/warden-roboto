package at.asitplus.attestation.android.exceptions

class AttestationException(message: String?, cause: Throwable? = null) : Throwable(message, cause)
class CertificateInvalidException(message: String, cause: Throwable? = null) : Throwable(message, cause)
class RevocationException(message: String?, cause: Throwable? = null) : Throwable(message, cause)
