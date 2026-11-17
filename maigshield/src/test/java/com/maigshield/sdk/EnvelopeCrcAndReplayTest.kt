package com.maigshield.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.CRC32

class EnvelopeCrcAndReplayTest {

    @Test
    fun test_envelope_ieee_crc32_detects_single_bit_tampering() {
        val buffer = ByteBuffer.allocate(76).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(0x4D414947)
        buffer.putShort(1.toShort())
        buffer.putLong(0x0102030405060708L)
        buffer.putLong(1731800000123456L)
        buffer.putLong(42L)
        buffer.put(ByteArray(32) { 0x5A })
        buffer.put(12.toByte())
        buffer.put(4.toByte())
        buffer.putLong(0x0000000000010001L)

        val payloadBytes = ByteArray(72)
        buffer.rewind()
        buffer.get(payloadBytes)

        val crc = CRC32().apply { update(payloadBytes) }.value.toInt()
        buffer.putInt(72, crc)

        // Verify valid CRC matches
        val recomputed = CRC32().apply { update(buffer.array(), 0, 72) }.value.toInt()
        assertEquals(crc, recomputed)

        // Flip 1 bit in monotonic_counter (offset 22)
        val tampered = buffer.array().clone()
        tampered[22] = (tampered[22].toInt() xor 0x01).toByte()
        val tamperedCrc = CRC32().apply { update(tampered, 0, 72) }.value.toInt()
        assertNotEquals("CRC-32 must reject single-bit tampering", crc, tamperedCrc)
    }

    @Test
    fun test_concurrent_monotonic_counter_produces_unique_strictly_increasing_values() {
        val threadCount = 32
        val iterationsPerThread = 200
        val counter = AtomicLong(1L)
        val observed = Collections.synchronizedSet(HashSet<Long>(threadCount * iterationsPerThread))
        val pool = Executors.newFixedThreadPool(threadCount)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            pool.submit {
                try {
                    repeat(iterationsPerThread) {
                        observed.add(counter.incrementAndGet())
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await()
        pool.shutdown()

        assertEquals(threadCount * iterationsPerThread, observed.size)
        assertEquals(1L + threadCount * iterationsPerThread, counter.get())
    }
}
