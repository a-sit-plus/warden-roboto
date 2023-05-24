package at.asitplus.attestation.android

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate


const val TEST_STATUS_LIST_PATH = "android-key-attestation/server/src/test/resources/status.json"

// Certificate generated by TestDPC with RSA Algorithm and StrongBox Security Level
val TEST_CERT = """
        -----BEGIN CERTIFICATE-----
        MIIB8zCCAXqgAwIBAgIRAMxm6ak3E7bmQ7JsFYeXhvcwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA0ZjdlYzg1N2U4MDU3
        NDdjMWIxZWRhYWVmODk1NDk2ZDAeFw0xOTA4MTQxOTU0MTBaFw0yOTA4MTExOTU0MTBaMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgMzJmYmJi
        NmRiOGM5MTdmMDdhYzlhYjZhZTQ4MTAzYWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQzg+sx9lLrkNIZwLYZerzL1bPK2zi75zFEuuI0fIr3
        5DJND1B4Z8RPZ3djzo3FOdAObqvoZ4CZVxcY3iQ1ffMMo2MwYTAdBgNVHQ4EFgQUzZOUqhJOO7wttSe9hYemjceVsgIwHwYDVR0jBBgwFoAUWlnI
        9iPzasns60heYXIP+h+Hz8owDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwUFz/AKheCOPaBiRGDk7L
        aSEDXVYmTr0VoU8TbIqrKGWiiMwsGEmW+Jdo8EcKVPIwAjAoO7n1ruFh+6mEaTAukc6T5BW4MnmYadkkFSIjzDAaJ6lAq+nmmGQ1KlZpqi4Z/VI=
        -----END CERTIFICATE-----
        """.trimIndent()


class RevocationTestFromGoogleSources : FreeSpec({

    "custom implementation" - {

        "load Test Serial" {
            val factory = CertificateFactory.getInstance("X509")
            val cert =
                factory.generateCertificate(ByteArrayInputStream(TEST_CERT.toByteArray(StandardCharsets.UTF_8))) as X509Certificate
            val serialNumber = cert.serialNumber
            val statusEntry =
                AndroidAttestationChecker.RevocationList.from(File(TEST_STATUS_LIST_PATH).inputStream())
                    .isRevoked(serialNumber)
            (statusEntry).shouldBeTrue()
        }


        "load Bad Serial" {
            AndroidAttestationChecker.RevocationList.from(File(TEST_STATUS_LIST_PATH).inputStream()).isRevoked(
                BigInteger.valueOf(0xbadbeef)
            ).shouldBeFalse()
        }
    }
})