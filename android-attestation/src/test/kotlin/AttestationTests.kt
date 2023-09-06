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
                    """
                    MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW
                    MBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpB
                    bmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCB
                    mDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2ds
                    ZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBS
                    b290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lac
                    qrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOj
                    zw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg
                    8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
                    """,
                    """
                    MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQH
                    DA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQg
                    S2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYD
                    VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYD
                    VQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49
                    AwEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7bPhGuEBSjZjBk
                    MB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8E
                    CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqRZ9pDMfDktQP
                    jgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7    
                    """,
                    """
                    MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW
                    MBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpB
                    bmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCB
                    mDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2ds
                    ZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBS
                    b290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lac
                    qrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOj
                    zw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg
                    8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==    
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
                        MIICozCCAkigAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDg4NGY4MTlkYzAxMjJkYjFm
                        NGFiZDI4YzllNzBmM2QwMCAXDTcwMDEwMTAwMDAwMFoYDzIxMDYwMjA3MDYyODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtl
                        eXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC9z3T/NtNDTc94eKdG3MKz4pIg+frP6j1zf3h4pE3fEZ0Ir
                        rXM+LagKuDV4HJoy4hHDSDrZD0youOREwxKKj6SjggFXMIIBUzAOBgNVHQ8BAf8EBAMCB4AwggE/BgorBgEEAdZ5AgERBIIB
                        LzCCASsCAQMKAQECAQQKAQEEEB3AKLZsumQV/HJ4eZrzHNsEADBfv4U9CAIGAYd/5YkQv4VFTwRNMEsxJTAjBB5hdC5hc2l0
                        cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaehCDEGAgEC
                        AgEDogMCAQOjBAICAQClCDEGAgEEAgECqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCDU9Nwdz6RJ5XFKxYBLU0JAfUxps3hH
                        RVc6cnRct9Wb9gEB/woBAAQgJ+BQyXYw7V5iEtU6QFzXeCnCpi75mTof21kND/tR7YC/hUEFAgMB+9C/hUIFAgMDFj+/hU4G
                        AgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNJADBGAiEAmSuuN2StHrBfO3J9tR45vcq/22Gn5cXKXt+DR45MBroCIQCu
                        abv+4ia9Y7w8ooHzql2OVYiDatqR9k5YUPABdVwd1g==
                        """,
                        """
                        MIIB8zCCAXqgAwIBAgIRALdlXIz6RNuRvfQY1AsxwIwwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBl
                        MGMzNTQ4YTQ3ZTczZjJhNzVmYjllZDZkYTViZjNlODAeFw0yMDA5MjgyMDE4NDhaFw0zMDA5MjYyMDE4NDhaMDkxDDAKBgNV
                        BAwMA1RFRTEpMCcGA1UEBRMgODg0ZjgxOWRjMDEyMmRiMWY0YWJkMjhjOWU3MGYzZDAwWTATBgcqhkjOPQIBBggqhkjOPQMB
                        BwNCAATmhTTiVhHty0CEC/ZOmZukvtlo0oVljIk/X66yucR13UfkzVzErNuM7Dznj0yGlSylkSTeJOYRUD82AYMQPwJFo2Mw
                        YTAdBgNVHQ4EFgQUPY4E/H/RzXhd1rVjbMikMLz6CLMwHwYDVR0jBBgwFoAUwlMBrj5jAa/ypZzVX4CUjgAyTjwwDwYDVR0T
                        AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDZwAwZAIwCsSg1hhIw9M3OFndg+2OzsCCCtyckDEYeQZL
                        Sc1w+LNAqsxkC6p/yhmgG+jyIDB7AjAyg7gzKF6ymsSQ+C55zoCS+InIaIK8ruz9RE4J7lC6SIvMCMXhmyoelkZ7aWARKaI=
                        """,
                        """
                        MIIDkzCCAXugAwIBAgIQFk/xbbOK0z0ZBF99wwx/zDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZi
                        MDQ1MB4XDTIwMDkyODIwMTc0OVoXDTMwMDkyNjIwMTc0OVowOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyBlMGMzNTQ4YTQ3
                        ZTczZjJhNzVmYjllZDZkYTViZjNlODB2MBAGByqGSM49AgEGBSuBBAAiA2IABJHz0uU3kbaMjfVN38GXDgIBLl4Gp7P59n6+
                        zmqoswoBrbrsCiFOWUU+B918FnEVcW86joLS+Ysn7msakvrHanJMJ4vDwD7/p+F6nkQ9J95FEkuq71oGTzCrs6SlCHu5XqNj
                        MGEwHQYDVR0OBBYEFMJTAa4+YwGv8qWc1V+AlI4AMk48MB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1Ud
                        EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQAnO5KNrbenSYxIOfzxH47CNi3Qz2O5+FoP
                        W7svNjggg/hZotSwbddpSVa+fdQYYYZdHMPNjQKXYaDxPPC2i/8KBhscq+TW1k9YKP+qNGMZ2CKzRIT0pByL0M5LQNbH6VxA
                        vzGlaCvTOIsDmlLyjzmT9QMtjWkmLKduISOa72hGMM4kCcIRKcgsq/s00whsOJ6IT27lp85AATuL9NvNE+kC1TZ96zEsR8Op
                        lur4euBmFoGzmtSFsZa9TNyc68RuJ+n/bY7iI77wXUz7ER6uj/sfnrjYJFclLjIjm8Mqp69IZ1nbJsKTgg0e5X4xeecNPLSM
                        p/hGqDOvNnSVbpri6Djm0ZWILk65BeRxANDUhICg/iuXnbSLIgPAIxsmniTV41nnIQ2nwDxVtfStsPzSWeEKkMTeta+Lu8jK
                        KVDcRTt2zoGx+JOQWaEWpOTUM/xZwnJamdHsKBWsskQhFMxLIPJbMeYAeCCswDTE+LQv31wDTxSrFVw/fcfVY6PSRZWoy+6Q
                        /zF3JATwQnYxNUchZG4suuy/ONPbOhD0VdzjkSyza6fomTw2F1G3c4jSQIiNV3OIxsxh4ja1ssJqMPuQzRcGGXxX8yQHrg+t
                        +Dxn32jFVhl5bxTeKuI6mWBYM+/qEBTBEXLNSmVdxrntFaPmiQcguBSFR1oHZyi/xS/jbYFZEQ==
                        """,
                        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcN
                        MTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                        AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2
                        tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                        nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC
                        8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                        JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8G
                        o3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                        RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2
                        QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                        IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEB
                        CwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                        h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcp
                        YEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                        D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fF
                        hE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                        oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw
                        9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                        ex0SdDrx+tWUDqG8At2JHA==
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
                        MIICpzCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIGQ3MWRmYjM1NjNlNWQ5Y2I0
                        NmRkMTJjMWJhMjI2YzM5MB4XDTIzMDQxNDE0MzAyMVoXDTQ4MDEwMTAwMDAwMFowJTEjMCEGA1UEAxMaaHR0cDovLzE5Mi4x
                        NjguMTc4LjMzOjgwODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqzk1wE4o3jS27/n40sW8ZExFxgXopGSxihSaLCUqG
                        HNsZoAvMTY96sQznDM0p4LoRKu5klGgE+4efkP4d+gyQo4IBWTCCAVUwDgYDVR0PAQH/BAQDAgeAMIIBQQYKKwYBBAHWeQIB
                        EQSCATEwggEtAgIAyAoBAQICAMgKAQEEEPcNdXPx9ZIH8fti6q6rHLoEADBfv4U9CAIGAYeALKLxv4VFTwRNMEsxJTAjBB5h
                        dC5hc2l0cGx1cy5hdHRlc3RhdGlvbl9jbGllbnQCAQExIgQgNLl2LE1skNSEMZQMV73nMUJYsmQg7+Fqx/cnTw0zCtUwgaeh
                        CDEGAgECAgEDogMCAQOjBAICAQClCDEGAgECAgEEqgMCAQG/g3cCBQC/hT4DAgEAv4VATDBKBCAPbnXIAYO13sB0sAVNQnHp
                        k4nr5LE2sIGd4fFQug/51wEB/woBAAQgNidLYFH3o3y3ufJGD1UzB8M0ZzGpxDl7RrvUI0SJSwi/hUEFAgMB+9C/hUIFAgMD
                        Fj+/hU4GAgQBNLChv4VPBgIEATSwoTAKBggqhkjOPQQDAgNHADBEAiAYJTfwNDCSiw/fob8VIBSNnXfaQaoyLxVmbaP/U5e2
                        AgIgAlngbOcR1syv1RP369hnI8cMh4xe1AFnB+H3Y9OVirQ=
                        """,
                        """
                        MIIBwzCCAWqgAwIBAgIRANcd+zVj5dnLRt0SwboibDkwCgYIKoZIzj0EAwIwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAG
                        A1UEAxMJRHJvaWQgQ0EzMB4XDTIzMDMyNjExNDk0OVoXDTIzMDUwMTExNDk0OVowOTEMMAoGA1UEChMDVEVFMSkwJwYDVQQD
                        EyBkNzFkZmIzNTYzZTVkOWNiNDZkZDEyYzFiYTIyNmMzOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJS3ylJ9AibrkDPP
                        /W4PBHmHU/e+yRiSTr4nLkojZzkBDWayhRI6PhrsN8Cetsp2EG2r2dQ60VnPvtvw9ElYYlGjYzBhMB0GA1UdDgQWBBQRvZZG
                        VqzjrxcT1lU/u8OGt6xJSjAfBgNVHSMEGDAWgBTEfQBQs7lkcRyV+Ok7Vmuti/ra9zAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud
                        DwEB/wQEAwICBDAKBggqhkjOPQQDAgNHADBEAiAjV7E60YcWRMdplr3lyh/M6nSHuADoGWdO10hP2h/81gIgTRHSnjjwPA3F
                        GlyYg8DGschrg3a7j8lEzLg2kRmzg9c=
                        """,
                        """
                        MIIB1jCCAVygAwIBAgITKqOs6sgL8zCfdZ1InqRvUR51szAKBggqhkjOPQQDAzApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIw
                        EAYDVQQDEwlEcm9pZCBDQTIwHhcNMjMwMzI3MjMxMzUyWhcNMjMwNTAxMjMxMzUxWjApMRMwEQYDVQQKEwpHb29nbGUgTExD
                        MRIwEAYDVQQDEwlEcm9pZCBDQTMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQGyo5Rgphmke9X1N+/0OBQzlUIsfWudjeX
                        WaFQOUl8VKN9y00pYQlyICzNAC4A9/f92tNhF3RkCn//Xfae9zcDo2MwYTAOBgNVHQ8BAf8EBAMCAgQwDwYDVR0TAQH/BAUw
                        AwEB/zAdBgNVHQ4EFgQUxH0AULO5ZHEclfjpO1ZrrYv62vcwHwYDVR0jBBgwFoAUu/g2rYmubOLlnpTw1bLX0nrkfEEwCgYI
                        KoZIzj0EAwMDaAAwZQIwffCbRJ9FCtNJopq2R2L0cpeoLKZTmu3SD2tcnU1CxBbEnhBA8Jl1giOBPsdB+VrPAjEA74XTlWF8
                        C2UmzwiCRxemo+tlw9EJ752ljAIwlUOWErA40tIGRe18736YdxM/zC8X
                        """,
                        """
                        MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4X
                        DTIyMDEyNjIyNDc1MloXDTM3MDEyMjIyNDc1MlowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0Ey
                        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuppxbZvJgwNXXe6qQKidXqUt1ooT8M6Q+ysWIwpduM2EalST8v/Cy2JN10aqTfUS
                        ThJha/oCtG+F9TUUviOch6RahrpjVyBdhopM9MFDlCfkiCkPCPGu2ODMj7O/bKnko2YwZDAdBgNVHQ4EFgQUu/g2rYmubOLl
                        npTw1bLX0nrkfEEwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwEgYDVR0TAQH/BAgwBgEB/wIBAjAOBgNVHQ8B
                        Af8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAIFxUiFHYfObqrJM0eeXI+kZFT57wBplhq+TEjd+78nIWbKvKGUFlvt7IuXH
                        zZ7YJdtSDs7lFtCsxXdrWEmLckxRDCRcth3Eb1leFespS35NAOd0Hekg8vy2G31OWAe567l6NdLjqytukcF4KAzHIRxoFivN
                        +tlkEJmg7EQw9D2wPq4KpBtug4oJE53R9bLCT5wSVj63hlzEY3hC0NoSAtp0kdthow86UFVzLqxEjR2B1MPCMlyIfoGyBgky
                        AWhd2gWN6pVeQ8RZoO5gfPmQuCsn8m9kv/dclFMWLaOawgS4kyAn9iRi2yYjEAI0VVi7u3XDgBVnowtYAn4gma5q4BdXgbWb
                        UTaMVVVZsepXKUpDpKzEfss6Iw0zx2Gql75zRDsgyuDyNUDzutvDMw8mgJmFkWjlkqkVM2diDZydzmgi8br2sJTLdG4lUwve
                        dIaLgjnIDEG1J8/5xcPVQJFgRf3m5XEZB4hjG3We/49p+JRVQSpE1+QzG0raYpdNsxBUO+41diQo7qC7S8w2J+TMeGdpKGjC
                        IzKjUDAy2+gOmZdZacanFN/03SydbKVHV0b/NYRWMa4VaZbomKON38IH2ep8pdj++nmSIXeWpQE8LnMEdnUFjvDzp0f0ELSX
                        VW2+5xbl+fcqWgmOupmU4+bxNJLtknLo49Bg5w9jNn7T7rkF
                        """,
                        """
                        MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcN
                        MTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
                        AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2
                        tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
                        nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC
                        8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
                        JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8G
                        o3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
                        RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2
                        QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
                        IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEB
                        CwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83U
                        h6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG+mEkN8/TA6p3cnoL/sPyz6evdjLlSeJ8rFBH6xWyIZCbrcp
                        YEJzXaUOEaxxXxgYz5/cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC/vA
                        D32KdNQ+c3N+vl2OTsUVMC1GiWkngNx1OO1+kXW+YTnnTUOtOIswUP/Vqd5SYgAImMAfY8U9/iIgkQj6T2W6FsScy94IN9fF
                        hE1UtzmLoBIuUFsVXJMTz+Jucth+IqoWFua9v1R93/k98p41pjtFX+H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe/A91
                        oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL+H7qJguBw09ojm6xNIrw2OocrDKsudk/okr/AwqEyPKw
                        9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK/xyZFiRcrPJPb41zgbQj9XAEyLKCH
                        ex0SdDrx+tWUDqG8At2JHA==
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
) = HardwareAttestationChecker(
    AndroidAttestationConfiguration(
        listOf(
            AndroidAttestationConfiguration.AppData(
                packageName = androidPackageName,
                signatureDigests = androidAppSignatureDigest,
                appVersion = androidAppVersion
            )
        ),
        androidVersion = androidVersion,
        patchLevel = androidPatchLevel,
        requireStrongBox = requireStrongBox,
        bootloaderUnlockAllowed = unlockedBootloaderAllowed,
        requireRollbackResistance = requireRollbackResistance
    )
)


fun String.decodeBase64ToArray() = Base64.decode(this)

