package com.maigshield.sdk

import com.maigshield.sdk.internal.crypto.SafeBase64
import com.maigshield.sdk.internal.crypto.StrongBoxSigner
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.junit.Assert.assertThrows

class HybridCryptoEnvelopeTest {

    @Test
    fun test_hybrid_encryption_and_diagnostic_decapsulation_roundtrip() {
        // 1. Generate RSA-2048 keypair representing the Bank Datacenter Server
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val bankKeyPair = kpg.generateKeyPair()

        // 2. Synthesize a 76-byte TelemetryEnvelope matching C++ layout
        val envelopeBuffer = ByteBuffer.allocate(76).order(ByteOrder.LITTLE_ENDIAN)
        envelopeBuffer.putInt(0x4D414947)                      // Magic "MAIG"
        envelopeBuffer.putShort(1.toShort())                   // Version 1
        envelopeBuffer.putLong(0x123456789ABCDEF0L)            // Salt
        envelopeBuffer.putLong(1731800000000000L)              // Monotonic TS
        envelopeBuffer.putLong(101L)                           // Monotonic Counter
        val mockHash = ByteArray(32) { (it + 1).toByte() }
        envelopeBuffer.put(mockHash)                           // Binding hash
        envelopeBuffer.put(25.toByte())                        // Bot score
        envelopeBuffer.put(10.toByte())                        // Duress score
        envelopeBuffer.putLong(0x0000000000000002L)            // Scrambled flags
        envelopeBuffer.putInt(0x11223344)                      // CRC32
        val rawEnvelope = envelopeBuffer.array()
        assertEquals(76, rawEnvelope.size)

        // 3. Perform Hybrid Encryption (AES-256-GCM + RSA-OAEP SHA-256)
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom())
        val aesKey = keyGen.generateKey()

        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaepParams = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        )
        rsaCipher.init(Cipher.ENCRYPT_MODE, bankKeyPair.public, oaepParams)
        val encapsulatedKey = rsaCipher.doFinal(aesKey.encoded)

        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        aesCipher.updateAAD(byteArrayOf(1))
        aesCipher.updateAAD(encapsulatedKey)
        val ciphertext = aesCipher.doFinal(rawEnvelope)

        val mockSignature = ByteArray(64) { 0x5A.toByte() }

        // 4. Pack into proof container
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.writeByte(1) // version
            dos.writeShort(encapsulatedKey.size)
            dos.write(encapsulatedKey)
            dos.write(iv)
            dos.writeInt(ciphertext.size)
            dos.write(ciphertext)
            dos.writeShort(mockSignature.size)
            dos.write(mockSignature)
        }
        val tokenBase64 = SafeBase64.encodeUrlSafe(baos.toByteArray())

        // 5. Decrypt using StrongBoxSigner diagnostic helper
        val diag = StrongBoxSigner.decryptProofTokenForDiagnostics(tokenBase64, bankKeyPair.private)

        // 6. Verify complete field fidelity
        assertEquals(0x4D414947, diag.magic)
        assertEquals(1, diag.envelopeVersion)
        assertEquals(0x123456789ABCDEF0L, diag.salt)
        assertEquals(1731800000000000L, diag.timestampNs)
        assertEquals(101L, diag.counter)
        assertEquals(25, diag.botScore)
        assertEquals(10, diag.duressScore)
        assertEquals(2L, diag.scrambledFlags)
        assertEquals(0x11223344, diag.crc32)
        assertEquals(mockHash.joinToString("") { "%02x".format(it) }, diag.bindingHashHex)
    }

    @Test
    fun test_aad_tampering_protocol_version_fails_gcm_authentication() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val bankKeyPair = kpg.generateKeyPair()

        val rawEnvelope = ByteArray(76) { 0x42 }
        val aesKey = KeyGenerator.getInstance("AES").apply { init(256, SecureRandom()) }.generateKey()
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsaCipher.init(
            Cipher.ENCRYPT_MODE,
            bankKeyPair.public,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        )
        val encapsulatedKey = rsaCipher.doFinal(aesKey.encoded)

        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        aesCipher.updateAAD(byteArrayOf(1))
        aesCipher.updateAAD(encapsulatedKey)
        val ciphertext = aesCipher.doFinal(rawEnvelope)

        // Tamper protocol_version from 1 -> 2 in the serialized container
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.writeByte(2)
            dos.writeShort(encapsulatedKey.size)
            dos.write(encapsulatedKey)
            dos.write(iv)
            dos.writeInt(ciphertext.size)
            dos.write(ciphertext)
            dos.writeShort(64)
            dos.write(ByteArray(64))
        }
        val tamperedToken = SafeBase64.encodeUrlSafe(baos.toByteArray())

        assertThrows(AEADBadTagException::class.java) {
            StrongBoxSigner.decryptProofTokenForDiagnostics(tamperedToken, bankKeyPair.private)
        }
    }

    @Test
    fun test_ciphertext_bitflip_fails_gcm_authentication() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val bankKeyPair = kpg.generateKeyPair()

        val rawEnvelope = ByteArray(76) { 0x11 }
        val aesKey = KeyGenerator.getInstance("AES").apply { init(256, SecureRandom()) }.generateKey()
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsaCipher.init(
            Cipher.ENCRYPT_MODE,
            bankKeyPair.public,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        )
        val encapsulatedKey = rsaCipher.doFinal(aesKey.encoded)

        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        aesCipher.updateAAD(byteArrayOf(1))
        aesCipher.updateAAD(encapsulatedKey)
        val ciphertext = aesCipher.doFinal(rawEnvelope)

        // Flip 1 bit in ciphertext
        ciphertext[10] = (ciphertext[10].toInt() xor 0x01).toByte()

        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.writeByte(1)
            dos.writeShort(encapsulatedKey.size)
            dos.write(encapsulatedKey)
            dos.write(iv)
            dos.writeInt(ciphertext.size)
            dos.write(ciphertext)
            dos.writeShort(64)
            dos.write(ByteArray(64))
        }
        val tamperedToken = SafeBase64.encodeUrlSafe(baos.toByteArray())

        assertThrows(AEADBadTagException::class.java) {
            StrongBoxSigner.decryptProofTokenForDiagnostics(tamperedToken, bankKeyPair.private)
        }
    }

    @Test
    fun test_wrong_server_private_key_fails_decapsulation() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val bankKeyPair = kpg.generateKeyPair()
        val attackerKeyPair = kpg.generateKeyPair()

        val rawEnvelope = ByteArray(76) { 0x33 }
        val aesKey = KeyGenerator.getInstance("AES").apply { init(256, SecureRandom()) }.generateKey()
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsaCipher.init(
            Cipher.ENCRYPT_MODE,
            bankKeyPair.public,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
        )
        val encapsulatedKey = rsaCipher.doFinal(aesKey.encoded)

        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        aesCipher.updateAAD(byteArrayOf(1))
        aesCipher.updateAAD(encapsulatedKey)
        val ciphertext = aesCipher.doFinal(rawEnvelope)

        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.writeByte(1)
            dos.writeShort(encapsulatedKey.size)
            dos.write(encapsulatedKey)
            dos.write(iv)
            dos.writeInt(ciphertext.size)
            dos.write(ciphertext)
            dos.writeShort(64)
            dos.write(ByteArray(64))
        }
        val token = SafeBase64.encodeUrlSafe(baos.toByteArray())

        assertThrows(Exception::class.java) {
            StrongBoxSigner.decryptProofTokenForDiagnostics(token, attackerKeyPair.private)
        }
    }
}
