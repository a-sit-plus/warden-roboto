package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.data.AttestationCreator
import at.asitplus.attestation.data.AttestationData
import at.asitplus.attestation.data.attestationCertChain
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlin.random.Random

val  fakeAttestationTests by testSuite{

    "Fake Attestation Test" - {
        val challenge = "42".encodeToByteArray()
        val packageName = "fa.ke.it.till.you.make.it"
        val signatureDigest = Random.nextBytes(32)
        val appVersion = 5
        val androidVersion = 11
        val patchLevel = PatchLevel(2021, 8)

        val attestationProof = AttestationCreator.createAttestation(
            challenge = challenge,
            packageName = packageName,
            signatureDigest = signatureDigest,
            appVersion = appVersion,
            androidVersion = androidVersion,
            androidPatchLevel = patchLevel.asSingleInt
        )

        val checker = HardwareAttestationChecker(
            AndroidAttestationConfiguration(
                AndroidAttestationConfiguration.AppData(
                    packageName = packageName,
                    signatureDigests = listOf(signatureDigest),
                    appVersion = appVersion),
                androidVersion = androidVersion,
                patchLevel = patchLevel,
                requireStrongBox = false,
                allowBootloaderUnlock = false,
                ignoreLeafValidity = false,
                hardwareAttestationTrustAnchors = setOf(attestationProof.last().publicKey)
            )
        )

        "Bug 77" {
            val borkedAttestation = AttestationCreator.createAttestation(
                challenge = challenge,
                packageName = packageName,
                signatureDigest = signatureDigest,
                appVersion = appVersion,
                androidVersion = androidVersion,
                vendorPatchLevel = 0,
            )

            HardwareAttestationChecker(
                AndroidAttestationConfiguration(
                    AndroidAttestationConfiguration.AppData(
                        packageName = packageName,
                        signatureDigests = listOf(signatureDigest),
                        appVersion = appVersion),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false,
                    hardwareAttestationTrustAnchors = setOf(borkedAttestation.last().publicKey)
                )).verifyAttestation(
                certificates = borkedAttestation,
                expectedChallenge = challenge
            )
        }

        val nokia = AttestationData(
            "Nokia X10",
            challengeB64 = "HcAotmy6ZBX8cnh5mvMc2w==",
            attestationProofB64 = listOf(
                """
                MIICozCCAkigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDg4NGY4MTlkYzAxMjJkYjFmNGFiZDI4
                YzllNzBmM2QwMCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3MDYyODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZ
                MBMGByqGSM49AgEGCCqGSM49AwEHA0IABC9z3T/NtNDTc94eKdG3MKz4pIg+frP6j1zf3h4pE3fEZ0IrrXM+LagKuDV4HJoy4hHDSDrZ
                D0youOREwxKKj6SjggFXMIIBUzAOBgNVHQ8BAf8EBAMCB4AwggE/BgorBgEEAdZ5AgERBIIBLzCCASsCAQMKAQECAQQKAQEEEB3AKLZs
                umQV/HJ4eZrzHNsEADBfv4U9CAIGAYd/5YkQv4VFTwRNMEsxJTAjBB5hdC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQg
                NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEGAgECAgEDogMCAQOjBAICAQClCDEGAgEEAgECqgMCAQG/g3cCBQC/
                hT4DAgEAv4VATDBKBCDU9Nwdz6RJ5XFKxYBLU0JAfUxps3hHRVc6cnRct9Wb9gEB/woBAAQgJ+BQyXYw7V5iEtU6QFzXeCnCpi75mTof
                21kND/tR7YC/hUEFAgMB+9C/hUIFAgMDFj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNJADBGAiEAmSuuN2StHrBfO3J9
                tR45vcq/22Gn5cXKXt+DR45MBroCIQCuabv+4ia9Y7w8ooHzql2OVYiDatqR9k5YUPABdVwd1g==
                """,
                """
                MIIB8zCCAXqgAwIBAgIRALdlXIz6RNuRvfQY1AsxwIwwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4
                YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODAeFw0yMDA5MjgyMDE4NDhaFw0zMDA5MjYyMDE4NDhaMDkxDDAKBgNVBAwMA1RFRTEpMCcG
                A1UEBRMgODg0ZjgxOWRjMDEyMmRiMWY0YWJkMjhjOWU3MGYzZDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmhTTiVhHty0CEC/ZO
                mZukvtlo0oVljIk/X66yucR13UfkzVzErNuM7Dznj0yGlSylkSTeJOYRUD82AYMQPwJFo2MwYTAdBgNVHQ4EFgQUPY4E/H/RzXhd1rVj
                bMikMLz6CLMwHwYDVR0jBBgwFoAUwlMBrj5jAa/ypZzVX4CUjgAyTjwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYI
                KoZIzj0EAwIDZwAwZAIwCsSg1hhIw9M3OFndg+2OzsCCCtyckDEYeQZLSc1w+LNAqsxkC6p/yhmgG+jyIDB7AjAyg7gzKF6ymsSQ+C55
                zoCS+InIaIK8ruz9RE4J7lC6SIvMCMXhmyoelkZ7aWARKaI=
                """,
                """
                MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4X
                DTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjll
                ZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+zmqoswoBrbrsCiFOWUU+B918
                FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNjMGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc
                1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0G
                CSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoPW7svNjggg/hZotSwbddpSVa+fdQYYYZdHMPNjQKXYaDxPPC2
                i/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxAvzGlaCvTOIsDmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq/s0
                0whsOJ6IT27lp85AATuL9NvNE+kC1TZ96zEsR8Oplur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIj
                m8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSMp/hGqDOvNnSVbpri6Djm0ZWILk65BeRxANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxV
                tfStsPzSWeEKkMTeta+Lu8jKKVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrFVw/
                fcfVY6PSRZWoy+6Q/zF3JATwQnYxNUchZG4suuy/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX
                8yQHrg+t+Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTBEXLNSmVdxrntFaPmiQcguBSFR1oHZyi/xS/jbYFZEQ==
                """,
                """
                MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIy
                MjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
                CgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pT
                y/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmF
                mBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPl
                XTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvma
                g8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2
                pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
                aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJ
                UYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIE
                MA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAme
                E6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcp
                YEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+
                c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsV
                XJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb
                6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUB
                ZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA==
                """
            ),
            isoDate = "2023-04-15T00:00:00Z",
            pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL3PdP8200NNz3h4p0bcwrPikiD5+s/qPXN/eHikTd8RnQiutcz4tqAq4NXgcmjLiEcNIOtkPTKi45ETDEoqPpA=="
        )

        "should work when the fake cert is configured as trust anchor" {
            checker.verifyAttestation(
                certificates = attestationProof,
                expectedChallenge = challenge
            )

        }

        "but not with a real cert from a real device" {

            shouldThrow<CertificateInvalidException> {
                checker.verifyAttestation(nokia.attestationCertChain, expectedChallenge = nokia.challenge)
            }.reason shouldBe CertificateInvalidException.Reason.TRUST
        }

        "and the fake attestation must not verify against the google root key" {
            val trustedChecker = HardwareAttestationChecker(
                AndroidAttestationConfiguration(
                    applications = listOf(
                        AndroidAttestationConfiguration.AppData(
                            packageName = packageName,
                            signatureDigests = listOf(signatureDigest),
                            appVersion = appVersion,
                        )
                    ),
                    androidVersion = androidVersion,
                    patchLevel = patchLevel,
                    requireStrongBox = false,
                    allowBootloaderUnlock = false,
                    ignoreLeafValidity = false
                )
            )
            shouldThrow<CertificateInvalidException> {
                trustedChecker.verifyAttestation(
                    certificates = attestationProof,
                    expectedChallenge = challenge
                )
            }.reason shouldBe CertificateInvalidException.Reason.TRUST
        }


    }

}