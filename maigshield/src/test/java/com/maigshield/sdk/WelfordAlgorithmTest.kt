package com.maigshield.sdk

import org.junit.Assert.assertEquals
import org.junit.Test
import kotlin.math.sqrt

class WelfordAlgorithmTest {

    class Welford {
        var count: Long = 0
        var mean: Double = 0.0
        var M2: Double = 0.0

        fun update(x: Double) {
            count++
            val delta = x - mean
            mean += delta / count
            val delta2 = x - mean
            M2 += delta * delta2
        }

        fun variance(): Double = if (count > 1) M2 / (count - 1) else 0.0
        fun stddev(): Double = sqrt(variance())
    }

    @Test
    fun constant_sensor_inputs_yield_zero_variance_detecting_bots() {
        val welford = Welford()
        // Simulated synthetic touch pressure or static stand readings
        repeat(20) {
            welford.update(1.0)
        }

        assertEquals(20L, welford.count)
        assertEquals(1.0, welford.mean, 1e-9)
        assertEquals(0.0, welford.variance(), 1e-9)
        assertEquals(0.0, welford.stddev(), 1e-9)
    }

    @Test
    fun fluctuating_human_tremors_calculate_statistically_correct_variance() {
        val welford = Welford()
        val data = doubleArrayOf(2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0)
        data.forEach { welford.update(it) }

        // Sample mean = 5.0, Sample variance = 32 / 7 = 4.571428...
        assertEquals(8L, welford.count)
        assertEquals(5.0, welford.mean, 1e-6)
        assertEquals(4.5714285714, welford.variance(), 1e-6)
        assertEquals(2.1380899, welford.stddev(), 1e-6)
    }
}
