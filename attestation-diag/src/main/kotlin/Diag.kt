package at.asitplus.attestation.android

import com.google.android.attestation.ParsedAttestationRecord
import java.io.File
import java.security.PublicKey
import java.security.cert.X509Certificate
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonPrimitive
import com.google.gson.JsonNull
import com.google.gson.JsonSerializer

fun main(args: Array<String>) {

    if (args.isEmpty()) {
        System.err.println("Certificate neither specified in a file (-f <path to PEM/Base64 cert>) nor as parameter <Base64 cert>!")
        System.exit(1)
    }
    val certB64 = if (args[0] == "-f") java.io.File(args[1]).readText() else args[0]

    val full = args.last() == "-v"


    @OptIn(ExperimentalStdlibApi::class, kotlin.io.encoding.ExperimentalEncodingApi::class)
    val gson: Gson = GsonBuilder().apply {

        registerTypeAdapter(ByteArray::class.java,
            JsonSerializer<ByteArray> { src, _, _ ->
                JsonPrimitive(src?.toHexString(HexFormat.UpperCase))
            })
        registerTypeAdapter(java.security.PublicKey::class.java, JsonSerializer<java.security.PublicKey> { src, _, _ ->
            com.google.gson.JsonObject().apply {
                add("algorithm", JsonPrimitive(src.algorithm))
                add("format", JsonPrimitive(src.format))
                add("encoded", JsonPrimitive(src.encoded.toHexString(HexFormat.UpperCase)))
            }
        })
        registerTypeAdapter(
            java.util.Optional::class.java,
            JsonSerializer<java.util.Optional<*>> { src, _, ctx ->
                if (src == null || src.isEmpty) {
                    if (!full) null else JsonNull.INSTANCE
                } else ctx.serialize(src.get())
            })
        registerTypeAdapter(
            java.security.cert.Certificate::class.java,
            JsonSerializer<java.security.cert.Certificate> { src, _, _ ->
                JsonPrimitive(src?.let { kotlin.io.encoding.Base64.encode(it.encoded) })
            })
        registerTypeAdapter(java.time.Instant::class.java, JsonSerializer<java.time.Instant> { src, _, _ ->
            JsonPrimitive(src?.toString())
        })
        if (!full) registerTypeAdapter(
            com.google.common.collect.ImmutableSet::class.java,
            JsonSerializer<com.google.common.collect.ImmutableSet<*>> { src, _, ctx ->
                if (src == null || src.isEmpty()) null
                else ctx.serialize(src)
            })

        disableJdkUnsafe()
        if (full) serializeNulls()
        setPrettyPrinting()
    }.create()


    println(
        gson.toJson(
            ParsedAttestationRecord.createParsedAttestationRecord(
                listOf(
                    java.security.cert.CertificateFactory.getInstance(
                        "X.509"
                    ).generateCertificate(
                        java.util.Base64.getMimeDecoder()
                            .decode(certB64.replace("\\n", "").replace("\\r", "").replace(" ", "")).inputStream()
                    ) as X509Certificate
                )
            )
        )
    )
}
