package com.bikemesh.ridemesh.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The plaintext audio payload carried inside an [Envelope] of type AUDIO.
 *
 * This is the thing that gets encrypted: we serialize an [AudioFrame], encrypt
 * the bytes, and put the ciphertext in [Envelope.payload]. Wrapping the raw PCM
 * in a tiny self-describing header (codec, rate, channels, duration) is what
 * lets us swap PCM16 for OPUS later (roadmap V0.5) without changing the
 * envelope or the transport — the receiver reads the codec field and decodes
 * accordingly. Overhead is 7 bytes on a ~640-byte frame (~1%).
 */
data class AudioFrame(
    val codec: AudioCodec,
    val sampleRateHz: Int,
    val channels: Int,
    val frameDurationMs: Int,
    val audio: ByteArray,
) {
    fun encode(): ByteArray {
        val buf = ByteBuffer.allocate(HEADER_BYTES + audio.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(codec.value.toByte())
        buf.putInt(sampleRateHz)
        buf.put(channels.coerceIn(0, 255).toByte())
        buf.put(frameDurationMs.coerceIn(0, 255).toByte())
        buf.put(audio)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AudioFrame) return false
        return codec == other.codec &&
            sampleRateHz == other.sampleRateHz &&
            channels == other.channels &&
            frameDurationMs == other.frameDurationMs &&
            audio.contentEquals(other.audio)
    }

    override fun hashCode(): Int {
        var result = codec.hashCode()
        result = 31 * result + sampleRateHz
        result = 31 * result + channels
        result = 31 * result + frameDurationMs
        result = 31 * result + audio.contentHashCode()
        return result
    }

    companion object {
        private const val HEADER_BYTES = 7 // codec(1) + rate(4) + channels(1) + dur(1)

        fun decode(bytes: ByteArray): AudioFrame? {
            if (bytes.size < HEADER_BYTES) return null
            return try {
                val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
                val codec = AudioCodec.fromValue(buf.get().toInt() and 0xFF)
                val rate = buf.int
                val channels = buf.get().toInt() and 0xFF
                val dur = buf.get().toInt() and 0xFF
                val audio = ByteArray(buf.remaining())
                buf.get(audio)
                AudioFrame(codec, rate, channels, dur, audio)
            } catch (_: Throwable) {
                null
            }
        }
    }
}
