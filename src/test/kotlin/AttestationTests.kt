package at.asitplus.attestation.android

import at.asitplus.attestation.android.exceptions.AttestationException
import at.asitplus.attestation.android.exceptions.CertificateInvalidException
import at.asitplus.attestation.data.AttestationData
import at.asitplus.attestation.data.attestationCertChain
import com.google.android.attestation.ParsedAttestationRecord
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.util.encoders.Base64
import java.sql.Date
import java.time.Duration


class AttestationTests : FreeSpec() {


    init {
        "TODO" {
            println("we still need unlocked bootloader testcases and non-hw-attested ones!")
        }

        "No HW attestation support" {
            AttestationData(
                "Android Emulator",
                challengeB64 = "RN9CjU7I5zpvCh7D3vi/aA==",
                attestationProofB64 = listOf(
                    """MIIC+jCCAqCgAwIBAgIBATAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCVVMxEzARBgNVB
                    AgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZ
                    DE7MDkGA1UEAwwyQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBJbnRlc
                    m1lZGlhdGUwHhcNNzAwMTAxMDAwMDAwWhcNNjkxMjMxMjM1OTU5WjAfMR0wGwYDVQQDDBRBb
                    mRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIEAthaOZ2+nZ
                    ZyYdoeLYNL5yZozzfMdrfrZcG2RI1juriVparubkzxZGCs4KcReh1aDhWFsDxQWYAeJLcFN8
                    rOjggFhMIIBXTALBgNVHQ8EBAMCB4AwggErBgorBgEEAdZ5AgERBIIBGzCCARcCAQQKAQACA
                    SkKAQAEEETfQo1OyOc6bwoew974v2gEADCB8qEIMQYCAQICAQOiAwIBA6MEAgIBAKUIMQYCA
                    QICAQSqAwIBAb+DdwIFAL+FPQgCBgGHj7zJmL+FPgMCAQC/hUBMMEoEIAAAAAAAAAAAAAAAA
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    AAAAAAAAL+FQQUCAwGtsL+FQgUCAwMVG7+FRU8ETTBLMSUwIwQeYXQuYXNpdHBsdXMuYXR0Z
                    XN0YXRpb25fY2xpZW50AgEBMSIEIDS5dixNbJDUhDGUDFe95zFCWLJkIO/hasf3J08NMwrVM
                    AAwHwYDVR0jBBgwFoAUP/ys1hqxOp6BILjVJRzFZbsekakwCgYIKoZIzj0EAwIDSAAwRQIgW
                    CsSigJsOLe9hli462AL/TuPqLuuIKelSVEe/PsnrWUCIQC+JExSC5l3slEBhDKxMD3otjwr0
                    DK0Jav50CzyK80ILg==
                    """,
                    """MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDV
                    QQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nb
                    GUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU
                    29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2M
                    DlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ
                    2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlI
                    FNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49A
                    wEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZ
                    jW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfB
                    gNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA
                    1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqR
                    Z9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7
                    """,
                    """MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVU
                    zETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UEC
                    gwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtle
                    XN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwM
                    TA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVB
                    AcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kc
                    m9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb
                    290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/S
                    Q59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEF
                    Mit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPM
                    A8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho
                    ++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytT
                    ySn502vQX3xvw==
                    """
                ),
                isoDate = "2023-04-18T00:00:00Z",
                pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgQC2Fo5nb6dlnJh2h4tg0vnJmjPN8x2t+tlwbZEjWO6uJWlqu5uTPFkYKzgpxF6HVoOFYWwPFBZgB4ktwU3ysw=="
            ).apply {
                shouldThrow<CertificateInvalidException> {
                    attestationService().verifyAttestation(
                        attestationCertChain,
                        verificationDate,
                        challenge
                    )
                }
            }
        }

        "Captured Real Devices" - {
            listOf(
                AttestationData(
                    "Nokia X10",
                    challengeB64 = "HcAotmy6ZBX8cnh5mvMc2w==",
                    attestationProofB64 = listOf(
                        """
                        MIICozCCAkigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDg4NGY4MTlkYzAxMjJkYjFmNGFiZDI4YzllNzBmM2QwMCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3MDY
                        yODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC9z3T/NtNDTc94eKdG3MKz4pIg+frP6j1zf3h4pE3fEZ0IrrXM+LagKuDV4HJ
                        oy4hHDSDrZD0youOREwxKKj6SjggFXMIIBUzAOBgNVHQ8BAf8EBAMCB4AwggE/BgorBgEEAdZ5AgERBIIBLzCCASsCAQMKAQECAQQKAQEEEB3AKLZsumQV/HJ4eZrzHNsEADBfv4U9CAIGAYd/5
                        YkQv4VFTwRNMEsxJTAjBB5hdC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEGAgECAgEDogMCAQOjBAICAQCl
                        CDEGAgEEAgECqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDU9Nwdz6RJ5XFKxYBLU0JAfUxps3hHRVc6cnRct9Wb9gEB/woBAAQgJ+BQyXYw7V5iEtU6QFzXeCnCpi75mTof21kND/tR7YC/hUE
                        FAgMB+9C/hUIFAgMDFj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNJADBGAiEAmSuuN2StHrBfO3J9tR45vcq/22Gn5cXKXt+DR45MBroCIQCuabv+4ia9Y7w8ooHzql2OVYiDat
                        qR9k5YUPABdVwd1g==
                        """,
                        """
                        MIIB8zCCAXqgAwIBAgIRALdlXIz6RNuRvfQY1AsxwIwwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODAeFw0yMDA5MjgyMDE
                        4NDhaFw0zMDA5MjYyMDE4NDhaMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgODg0ZjgxOWRjMDEyMmRiMWY0YWJkMjhjOWU3MGYzZDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmhTTiVh
                        Hty0CEC/ZOmZukvtlo0oVljIk/X66yucR13UfkzVzErNuM7Dznj0yGlSylkSTeJOYRUD82AYMQPwJFo2MwYTAdBgNVHQ4EFgQUPY4E/H/RzXhd1rVjbMikMLz6CLMwHwYDVR0jBBgwFoAUwlMBr
                        j5jAa/ypZzVX4CUjgAyTjwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwCsSg1hhIw9M3OFndg+2OzsCCCtyckDEYeQZLSc1w+LNAqsxkC6p/yhmg
                        G+jyIDB7AjAyg7gzKF6ymsSQ+C55zoCS+InIaIK8ruz9RE4J7lC6SIvMCMXhmyoelkZ7aWARKaI=
                        """,
                        """
                        MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoGA1U
                        EDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+zmqoswoBrbrsCi
                        FOWUU+B918FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNjMGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4
                        QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoPW7svNjggg/hZotSwbddp
                        SVa+fdQYYYZdHMPNjQKXYaDxPPC2i/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxAvzGlaCvTOIsDmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq/s00whsOJ6IT27lp85
                        AATuL9NvNE+kC1TZ96zEsR8Oplur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIjm8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSMp/hGqDOvNnSVbpri6Djm0ZWILk
                        65BeRxANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jKKVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrF
                        Vw/fcfVY6PSRZWoy+6Q/zF3JATwQnYxNUchZG4suuy/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX8yQHrg+t+Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTB
                        EXLNSmVdxrntFaPmiQcguBSFR1oHZyi/xS/jbYFZEQ==
                        """,
                        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTI
                        wMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlR
                        fdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC
                        4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS
                        +tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVt
                        CLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8
                        WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDA
                        gIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXE
                        ydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZ
                        qZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1
                        R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/A
                        wqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWUDqG8At2JHA==
                        """
                    ),
                    isoDate = "2023-04-15T00:00:00Z",
                    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL3PdP8200NNz3h4p0bcwrPikiD5+s/qPXN/eHikTd8RnQiutcz4tqAq4NXgcmjLiEcNIOtkPTKi45ETDEoqPpA=="
                ),
                AttestationData(
                    "Pixel 6",
                    challengeB64 = "9w11c/H1kgfx+2Lqrqscug==",
                    attestationProofB64 = listOf(
                        """
                        MIICpzCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGQ3MWRmYjM1NjNlNWQ5Y2I0NmRkMTJjMWJhMjI2YzM5MB4XDTIzMDQxNDE0MzAyMVoXDTQ4M
                        DEwMTAwMDAwMFowJTEjMCEGA1UEAxMaaHR0cDovLzE5Mi4xNjguMTc4LjMzOjgwODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqzk1wE4o3jS27/n40sW8ZExFxgXopGSxihSaLCUqGHN
                        sZoAvMTY96sQznDM0p4LoRKu5klGgE+4efkP4d+gyQo4IBWTCCAVUwDgYDVR0PAQH/BAQDAgeAMIIBQQYKKwYBBAHWeQIBEQSCATEwggEtAgIAyAoBAQICAMgKAQEEEPcNdXPx9ZIH8fti6q6
                        rHLoEADBfv4U9CAIGAYeALKLxv4VFTwRNMEsxJTAjBB5hdC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEG
                        AgECAgEDogMCAQOjBAICAQClCDEGAgECAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCAPbnXIAYO13sB0sAVNQnHpk4nr5LE2sIGd4fFQug/51wEB/woBAAQgNidLYFH3o3y3ufJGD1UzB
                        8M0ZzGpxDl7RrvUI0SJSwi/hUEFAgMB+9C/hUIFAgMDFj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNHADBEAiAYJTfwNDCSiw/fob8VIBSNnXfaQaoyLxVmbaP/U5e2AgIgAl
                        ngbOcR1syv1RP369hnI8cMh4xe1AFnB+H3Y9OVirQ=
                        """,
                        """
                        MIIBwzCCAWqgAwIBAgIRANcd+zVj5dnLRt0SwboibDkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMB4XDTIzMDMyNjExNDk0OVoXDTIzM
                        DUwMTExNDk0OVowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQDEyBkNzFkZmIzNTYzZTVkOWNiNDZkZDEyYzFiYTIyNmMzOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJS3ylJ9AibrkDPP/W
                        4PBHmHU/e+yRiSTr4nLkojZzkBDWayhRI6PhrsN8Cetsp2EG2r2dQ60VnPvtvw9ElYYlGjYzBhMB0GA1UdDgQWBBQRvZZGVqzjrxcT1lU/u8OGt6xJSjAfBgNVHSMEGDAWgBTEfQBQs7lkcRy
                        V+Ok7Vmuti/ra9zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDAKBggqhkjOPQQDAgNHADBEAiAjV7E60YcWRMdplr3lyh/M6nSHuADoGWdO10hP2h/81gIgTRHSnjjwPA3FGlyY
                        g8DGschrg3a7j8lEzLg2kRmzg9c=
                        """,
                        """
                        MIIB1jCCAVygAwIBAgITKqOs6sgL8zCfdZ1InqRvUR51szAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTIwHhcNMjMwMzI3MjMxMzUyWhcNM
                        jMwNTAxMjMxMzUxWjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGyo5Rgphmke9X1N+/0OBQzlUIsfWudjeXWa
                        FQOUl8VKN9y00pYQlyICzNAC4A9/f92tNhF3RkCn//Xfae9zcDo2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxH0AULO5ZHEclfjpO1ZrrYv62vcwHwY
                        DVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYIKoZIzj0EAwMDaAAwZQIwffCbRJ9FCtNJopq2R2L0cpeoLKZTmu3SD2tcnU1CxBbEnhBA8Jl1giOBPsdB+VrPAjEA74XTlWF8C2Um
                        zwiCRxemo+tlw9EJ752ljAIwlUOWErA40tIGRe18736YdxM/zC8X
                        """,
                        """
                        MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA
                        1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUSTh
                        Jha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLlnpTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8
                        aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXHzZ7Y
                        JdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN+tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0
                        NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgkyAWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWbUTaMVV
                        VZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwvedIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+Q
                        zG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjCIzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSXVW2+5xbl
                        +fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF
                        """,
                        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDV
                        QQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tq
                        w1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRx
                        B/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvs
                        BslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er
                        5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/b
                        kwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAM
                        BAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6Wszodm
                        MkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3
                        UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vAD32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoB
                        IuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJgu
                        Bw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx+tWU
                        DqG8At2JHA==
                        """
                    ),
                    isoDate = "2023-04-15T00:00:00Z",
                    pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqs5NcBOKN40tu/5+NLFvGRMRcYF6KRksYoUmiwlKhhzbGaALzE2PerEM5wzNKeC6ESruZJRoBPuHn5D+HfoMkA=="
                ),

                ).forEach { recordedAttestation ->

                recordedAttestation.name - {


                    "OK" - {
                        "enforce locked bootloader" {
                            attestationService(unlockedBootloaderAllowed = false).verifyAttestation(
                                recordedAttestation.attestationCertChain,
                                recordedAttestation.verificationDate,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<ParsedAttestationRecord>()
                        }

                        "allow unlocked bootloader" {
                            attestationService(unlockedBootloaderAllowed = true).verifyAttestation(
                                recordedAttestation.attestationCertChain,
                                recordedAttestation.verificationDate,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<ParsedAttestationRecord>()
                        }

                        "no version check" {
                            attestationService(androidVersion = null).verifyAttestation(
                                recordedAttestation.attestationCertChain,
                                recordedAttestation.verificationDate,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<ParsedAttestationRecord>()
                        }

                        "no patch level" {
                            attestationService(androidPatchLevel = null).verifyAttestation(
                                recordedAttestation.attestationCertChain,
                                recordedAttestation.verificationDate,
                                recordedAttestation.challenge
                            ).shouldBeInstanceOf<ParsedAttestationRecord>()
                        }
                    }

                    "Fail" - {
                        val service = attestationService(unlockedBootloaderAllowed = false)

                        "borked cert chain" {
                            shouldThrow<CertificateInvalidException> {
                                service.verifyAttestation(
                                    listOf(recordedAttestation.attestationCertChain[0]),
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                            shouldThrow<CertificateInvalidException> {
                                service.verifyAttestation(
                                    recordedAttestation.attestationCertChain.subList(0, 1),
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                            shouldThrow<CertificateInvalidException> {
                                service.verifyAttestation(
                                    recordedAttestation.attestationCertChain.subList(0, 2),
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "require StrongBox" {
                            shouldThrow<AttestationException> {
                                attestationService(requireStrongBox = true).verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "time of verification" - {
                            "too early" {
                                shouldThrow<CertificateInvalidException> {
                                    service.verifyAttestation(
                                        recordedAttestation.attestationCertChain,
                                        Date.from(
                                            recordedAttestation.verificationDate.toInstant()
                                                .minus(Duration.ofDays(30000))
                                        ),
                                        recordedAttestation.challenge
                                    )
                                }
                            }

                            "too late" {
                                shouldThrow<CertificateInvalidException> {
                                    service.verifyAttestation(
                                        recordedAttestation.attestationCertChain,
                                        Date.from(
                                            recordedAttestation.verificationDate.toInstant()
                                                .plus(Duration.ofDays(30000))
                                        ),
                                        recordedAttestation.challenge
                                    )
                                }
                            }
                        }

                        "package name" {
                            shouldThrow<AttestationException> {
                                attestationService(androidPackageName = "org.wrong.package.name").verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "wrong signature digests" {
                            shouldThrow<AttestationException> {
                                attestationService(
                                    androidAppSignatureDigest = listOf(
                                        byteArrayOf(0, 32, 55, 29, 120, 22, 0),
                                        /*this one's an invalid digest and must not affect the tests*/
                                        "LvfTC77F/uSecSfJDeLdxQ3gZrVLHX8+NNBp7AiUO0E=".decodeBase64ToArray()!!
                                    )
                                ).verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "no signature digests, cannot instantiate" {
                            shouldThrow<AttestationException> {
                                attestationService(androidAppSignatureDigest = listOf())
                            }
                        }



                        "app version" {
                            shouldThrow<AttestationException> {
                                attestationService(androidVersion = 200000).verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "patch level" {
                            shouldThrow<AttestationException> {
                                attestationService(androidPatchLevel = PatchLevel(2030, 1)).verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }

                        "rollback resistance" {
                            shouldThrow<AttestationException> {
                                attestationService(requireRollbackResistance = true).verifyAttestation(
                                    recordedAttestation.attestationCertChain,
                                    recordedAttestation.verificationDate,
                                    recordedAttestation.challenge
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

fun attestationService(
    androidPackageName: String = "at.asitplus.attestation_client",
    androidAppSignatureDigest: List<ByteArray> = listOf(
        "NLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtU=".decodeBase64ToArray(),
        /*this one's an invalid digest and must not affect the tests*/
        "LvfTC77F/uSecSfJDeLdxQ3gZrVLHX8+NNBp7AiUO0E=".decodeBase64ToArray()
    ),
    androidVersion: Int? = 10000,
    androidAppVersion: Int? = 1,
    androidPatchLevel: PatchLevel? = PatchLevel(2021, 8),
    requireStrongBox: Boolean = false,
    unlockedBootloaderAllowed: Boolean = false,
    requireRollbackResistance: Boolean = false
) = AndroidAttestationChecker(
    AndroidAttestationConfiguration(
        packageName = androidPackageName,
        signatureDigests = androidAppSignatureDigest,
        appVersion = androidAppVersion,
        androidVersion = androidVersion,
        patchLevel = androidPatchLevel,
        requireStrongBox = requireStrongBox,
        bootloaderUnlockAllowed = unlockedBootloaderAllowed,
        requireRollbackResistance = requireRollbackResistance
    )
)


fun String.decodeBase64ToArray() = Base64.decode(this)

