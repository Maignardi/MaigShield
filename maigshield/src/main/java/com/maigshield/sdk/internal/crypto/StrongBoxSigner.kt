package com.maigshield.sdk.internal.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class StrongBoxSigner internal constructor(
    private val context: Context,
    private val serverPublicKeyPem: String,
    private val enableStrongBox: Boolean = true,
    private val enforceAttestation: Boolean = true
) {

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }

    private val bankPublicKey: PublicKey by lazy {
        parsePublicKeyFromPem(serverPublicKeyPem)
    }

    private val secureRandom = SecureRandom()
    private val keyGenLock = Any()

    init {
        ensureAttestationKeyExists()
    }

    private fun ensureAttestationKeyExists() {
        synchronized(keyGenLock) {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateHardwareKey(attemptStrongBox = enableStrongBox)
            }
        }
    }

    private fun generateHardwareKey(attemptStrongBox: Boolean) {
        try {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )

            val challenge = ByteArray(32).apply {
                secureRandom.nextBytes(this)
            }

            val specBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)

            if (enforceAttestation) {
                specBuilder.setAttestationChallenge(challenge)
            }

            if (attemptStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    specBuilder.setIsStrongBoxBacked(true)
                    kpg.initialize(specBuilder.build())
                    kpg.generateKeyPair()
                    return
                } catch (e: Exception) {
                    if (e is StrongBoxUnavailableException ||
                        e.cause is StrongBoxUnavailableException ||
                        e.message?.contains("StrongBox", ignoreCase = true) == true
                    ) {
                        // Fallback gracefully to standard hardware TEE
                        generateHardwareKey(attemptStrongBox = false)
                        return
                    }
                    throw e
                }
            }

            specBuilder.setIsStrongBoxBacked(false)
            kpg.initialize(specBuilder.build())
            kpg.generateKeyPair()
        } catch (e: Exception) {
            throw SecurityException("Failed to generate Android Keystore Hardware Attestation key", e)
        }
    }

    fun getAttestationCertificateChain(): List<Certificate> {
        val chain = keyStore.getCertificateChain(KEY_ALIAS)
        return chain?.toList() ?: emptyList()
    }

    fun signAndEncryptEnvelope(rawEnvelope: ByteArray): String {
        // 1. Generate ephemeral 256-bit AES key
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, secureRandom)
        val ephemeralAesKey: SecretKey = keyGen.generateKey()

        // 2. Encapsulate AES key using Bank's Public Key (RSA-OAEP SHA-256)
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaepParams = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        )
        rsaCipher.init(Cipher.ENCRYPT_MODE, bankPublicKey, oaepParams)
        val encapsulatedKey = rsaCipher.doFinal(ephemeralAesKey.encoded)

        // 3. Encrypt raw binary envelope using AES-256-GCM with AAD binding
        val iv = ByteArray(GCM_IV_LENGTH).apply {
            secureRandom.nextBytes(this)
        }
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        aesCipher.init(Cipher.ENCRYPT_MODE, ephemeralAesKey, gcmSpec)
        aesCipher.updateAAD(byteArrayOf(PROOF_PROTOCOL_VERSION.toByte()))
        aesCipher.updateAAD(encapsulatedKey)
        val ciphertext = aesCipher.doFinal(rawEnvelope)
        rawEnvelope.fill(0)

        // 4. Sign (EncapsulatedKey + IV + Ciphertext) via StrongBox / TEE ECDSA
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("Hardware signing key missing in Keystore")

        val signatureEngine = Signature.getInstance("SHA256withECDSA")
        signatureEngine.initSign(privateKey)
        signatureEngine.update(encapsulatedKey)
        signatureEngine.update(iv)
        signatureEngine.update(ciphertext)
        val hardwareSignature = signatureEngine.sign()

        // 5. Serialize proof container into compact binary
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.writeByte(PROOF_PROTOCOL_VERSION)
            dos.writeShort(encapsulatedKey.size)
            dos.write(encapsulatedKey)
            dos.write(iv)
            dos.writeInt(ciphertext.size)
            dos.write(ciphertext)
            dos.writeShort(hardwareSignature.size)
            dos.write(hardwareSignature)
        }

        return SafeBase64.encodeUrlSafe(baos.toByteArray())
    }

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS = "com.maigshield.key.attestation.v1"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val PROOF_PROTOCOL_VERSION = 1

        fun parsePublicKeyFromPem(pem: String): PublicKey {
            val cleanPem = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")

            val decodedKey = SafeBase64.decodeStandard(cleanPem)
            val keySpec = X509EncodedKeySpec(decodedKey)

            return try {
                val kf = KeyFactory.getInstance("RSA")
                kf.generatePublic(keySpec)
            } catch (e: Exception) {
                val kf = KeyFactory.getInstance("EC")
                kf.generatePublic(keySpec)
            }
        }

        /**
         * Diagnostic helper to decrypt a generated proof token using a test RSA Private Key.
         * Used exclusively by the local sample diagnostic dashboard.
         */
        @JvmStatic
        fun decryptProofTokenForDiagnostics(
            proofTokenBase64: String,
            privateKey: PrivateKey
        ): DecryptedProofDiagnostic {
            val rawBytes = SafeBase64.decodeUrlSafe(proofTokenBase64)
            val dis = DataInputStream(ByteArrayInputStream(rawBytes))

            val version = dis.readByte().toInt()
            val encKeyLen = dis.readShort().toInt() and 0xFFFF
            val encapsulatedKey = ByteArray(encKeyLen)
            dis.readFully(encapsulatedKey)

            val iv = ByteArray(GCM_IV_LENGTH)
            dis.readFully(iv)

            val cipherLen = dis.readInt()
            val ciphertext = ByteArray(cipherLen)
            dis.readFully(ciphertext)

            val sigLen = dis.readShort().toInt() and 0xFFFF
            val signature = ByteArray(sigLen)
            dis.readFully(signature)

            // Decapsulate AES key
            val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            val oaepParams = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            )
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams)
            val aesKeyBytes = rsaCipher.doFinal(encapsulatedKey)
            val ephemeralAesKey = SecretKeySpec(aesKeyBytes, "AES")

            // Decrypt binary envelope (verify AAD matches version + encapsulated key)
            val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            aesCipher.init(Cipher.DECRYPT_MODE, ephemeralAesKey, gcmSpec)
            aesCipher.updateAAD(byteArrayOf(version.toByte()))
            aesCipher.updateAAD(encapsulatedKey)
            val rawEnvelope = aesCipher.doFinal(ciphertext)

            // Parse 76-byte TelemetryEnvelope
            val bb = ByteBuffer.wrap(rawEnvelope).order(ByteOrder.LITTLE_ENDIAN)
            val magic = bb.int
            val envelopeVersion = bb.short
            val salt = bb.long
            val timestampNs = bb.long
            val counter = bb.long
            val bindingHash = ByteArray(32)
            bb.get(bindingHash)
            val botScore = bb.get().toInt() and 0xFF
            val duressScore = bb.get().toInt() and 0xFF
            val scrambledFlags = bb.long
            val crc32 = bb.int

            return DecryptedProofDiagnostic(
                version = version,
                magic = magic,
                envelopeVersion = envelopeVersion.toInt(),
                salt = salt,
                timestampNs = timestampNs,
                counter = counter,
                bindingHashHex = bindingHash.joinToString("") { "%02x".format(it) },
                botScore = botScore,
                duressScore = duressScore,
                scrambledFlags = scrambledFlags,
                crc32 = crc32,
                hardwareSignatureHex = signature.joinToString("") { "%02x".format(it) }
            )
        }
    }
}

data class DecryptedProofDiagnostic(
    val version: Int,
    val magic: Int,
    val envelopeVersion: Int,
    val salt: Long,
    val timestampNs: Long,
    val counter: Long,
    val bindingHashHex: String,
    val botScore: Int,
    val duressScore: Int,
    val scrambledFlags: Long,
    val crc32: Int,
    val hardwareSignatureHex: String
)
