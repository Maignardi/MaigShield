package com.maigshield.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class TokenPackerPolymorphismTest {

    // Mirror of the PRNG Fisher-Yates algorithm implemented in token_packer.cpp
    private fun generateBitPermutation(seed: Long): IntArray {
        val perm = IntArray(64) { it }
        var state = if (seed != 0L) seed else 0x5EEDBEEF12345678L

        fun prngNext(): Long {
            state = state xor (state ushr 12)
            state = state xor (state shl 25)
            state = state xor (state ushr 27)
            return state * 0x2545F4914F6CDD1DL
        }

        for (i in 63 downTo 1) {
            val raw = prngNext()
            val positive = if (raw < 0) -raw else raw
            val j = (positive % (i + 1)).toInt()
            val temp = perm[i]
            perm[i] = perm[j]
            perm[j] = temp
        }
        return perm
    }

    private fun scrambleFlags(rawFlags: Long, perm: IntArray): Long {
        var scrambled = 0L
        for (i in 0 until 64) {
            if ((rawFlags ushr i) and 1L != 0L) {
                scrambled = scrambled or (1L shl perm[i])
            }
        }
        return scrambled
    }

    private fun unscrambleFlags(scrambled: Long, perm: IntArray): Long {
        var original = 0L
        for (i in 0 until 64) {
            if ((scrambled ushr perm[i]) and 1L != 0L) {
                original = original or (1L shl i)
            }
        }
        return original
    }

    @Test
    fun test_all_64_individual_canary_bits_roundtrip_perfectly() {
        val salt: Long = 0x123456789ABCDEF0L
        val timestampNs: Long = 1731800000000000L
        val codeChecksum: Long = 0x811C9DC5L

        val seed: Long = salt xor timestampNs xor codeChecksum
        val perm = generateBitPermutation(seed)

        for (bit in 0 until 64) {
            val originalFlag = 1L shl bit
            val scrambled = scrambleFlags(originalFlag, perm)
            val recovered = unscrambleFlags(scrambled, perm)

            assertEquals("Bit $bit failed to round-trip!", originalFlag, recovered)
        }
    }

    @Test
    fun test_composite_attack_flags_roundtrip_perfectly() {
        val salt: Long = 0x1122334455667788L
        val timestampNs: Long = 9988776655443322L
        val codeChecksum: Long = 0x7E3779B9L

        val seed: Long = salt xor timestampNs xor codeChecksum
        val perm = generateBitPermutation(seed)

        val testCases = listOf(
            0L,
            -1L, // All 64 bits set (0xFFFFFFFFFFFFFFFF)
            0x5555555555555555L,
            0x2AAAAAAAAAAAAAAAL,
            (1L shl 0) or (1L shl 1) or (1L shl 7) or (1L shl 16) or (1L shl 18)
        )

        for (flags in testCases) {
            val scrambled = scrambleFlags(flags, perm)
            val recovered = unscrambleFlags(scrambled, perm)
            assertEquals("Composite mask $flags failed to recover!", flags, recovered)
        }
    }

    @Test
    fun test_modified_code_checksum_scrambles_to_invalid_permutation() {
        val salt: Long = 0x3AFEBABE12345678L
        val timestampNs: Long = 554433221100L
        val expectedCodeChecksum: Long = 0x7E3779B9L
        val tamperedCodeChecksum: Long = 0x7E3779BAL // 1 bit altered by attacker NOP patch

        val legitimateSeed: Long = salt xor timestampNs xor expectedCodeChecksum
        val tamperedSeed: Long = salt xor timestampNs xor tamperedCodeChecksum

        val legPerm = generateBitPermutation(legitimateSeed)
        val tamperedPerm = generateBitPermutation(tamperedSeed)

        val sensitiveFlag = 1L shl 1 // FLAG_FRIDA_AGENT_MAPPED
        val scrambledWithTamperedCode = scrambleFlags(sensitiveFlag, tamperedPerm)

        // Server unscrambles using expected legitimate code checksum
        val recoveredByServer = unscrambleFlags(scrambledWithTamperedCode, legPerm)

        // Tampering must NOT yield original flag position
        assertNotEquals(sensitiveFlag, recoveredByServer)
    }
}
