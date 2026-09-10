package com.bikemesh.ridemesh.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class EnvelopeTest {

    private fun sample(payload: ByteArray, nonce: ByteArray = ByteArray(0)): Envelope =
        Envelope(
            protocolVersion = Envelope.PROTOCOL_VERSION,
            packetId = UUID.randomUUID(),
            originNodeId = UUID.randomUUID(),
            previousHopNodeId = Envelope.NONE_UUID,
            rideId = "RIDE42",
            destinationNodeId = Envelope.NONE_UUID,
            packetType = PacketType.AUDIO,
            ttl = 4,
            hopCount = 0,
            sequence = 99L,
            timestampMs = 123_456_789L,
            priority = Priority.HIGH,
            flags = 0,
            encryption = if (nonce.isEmpty()) EncryptionMode.NONE else EncryptionMode.AEAD_GROUP,
            keyEpoch = 3,
            nonce = nonce,
            payload = payload,
        )

    @Test
    fun envelopeRoundTripPreservesEveryField() {
        val payload = ByteArray(640) { (it % 127).toByte() }
        val nonce = ByteArray(12) { (it + 1).toByte() }
        val original = sample(payload, nonce)

        val decoded = Envelope.decode(original.encode())
        assertNotNull(decoded)
        decoded!!
        assertEquals(original.protocolVersion, decoded.protocolVersion)
        assertEquals(original.packetId, decoded.packetId)
        assertEquals(original.originNodeId, decoded.originNodeId)
        assertEquals(original.previousHopNodeId, decoded.previousHopNodeId)
        assertEquals(original.rideId, decoded.rideId)
        assertEquals(original.destinationNodeId, decoded.destinationNodeId)
        assertEquals(original.packetType, decoded.packetType)
        assertEquals(original.ttl, decoded.ttl)
        assertEquals(original.hopCount, decoded.hopCount)
        assertEquals(original.sequence, decoded.sequence)
        assertEquals(original.timestampMs, decoded.timestampMs)
        assertEquals(original.priority, decoded.priority)
        assertEquals(original.encryption, decoded.encryption)
        assertEquals(original.keyEpoch, decoded.keyEpoch)
        assertArrayEquals(original.nonce, decoded.nonce)
        assertArrayEquals(original.payload, decoded.payload)
    }

    @Test
    fun forwardedByDecrementsTtlAndBumpsHopAndSetsPreviousHop() {
        val me = UUID.randomUUID()
        val original = sample(byteArrayOf(1, 2, 3))
        val fwd = original.forwardedBy(me)

        assertEquals(original.ttl - 1, fwd.ttl)
        assertEquals(original.hopCount + 1, fwd.hopCount)
        assertEquals(me, fwd.previousHopNodeId)
        // Identity-preserving fields must NOT change on relay.
        assertEquals(original.packetId, fwd.packetId)
        assertEquals(original.originNodeId, fwd.originNodeId)
        assertArrayEquals(original.payload, fwd.payload)
        assertArrayEquals(original.nonce, fwd.nonce)
    }

    @Test
    fun ttlNeverGoesNegative() {
        val z = sample(byteArrayOf(9)).copy(ttl = 0)
        assertEquals(0, z.forwardedBy(UUID.randomUUID()).ttl)
    }

    @Test
    fun decodeRejectsGarbageAndTruncation() {
        assertNull(Envelope.decode(ByteArray(4)))
        assertNull(Envelope.decode(ByteArray(200) { 0 })) // bad magic
        val good = sample(byteArrayOf(1, 2, 3, 4)).encode()
        assertNull(Envelope.decode(good.copyOf(good.size - 2))) // truncated payload
    }

    @Test
    fun audioFrameRoundTrip() {
        val pcm = ByteArray(320) { (it % 100 - 50).toByte() }
        val frame = AudioFrame(AudioCodec.PCM16, 16_000, 1, 20, pcm)
        val decoded = AudioFrame.decode(frame.encode())
        assertNotNull(decoded)
        decoded!!
        assertEquals(AudioCodec.PCM16, decoded.codec)
        assertEquals(16_000, decoded.sampleRateHz)
        assertEquals(1, decoded.channels)
        assertEquals(20, decoded.frameDurationMs)
        assertArrayEquals(pcm, decoded.audio)
    }

    @Test
    fun headerStaysCleartextSoRelaysCanReadRoutingWithoutTheKey() {
        // Even with an encrypted payload, ttl/packetId/origin are plainly decodable.
        val original = sample(ByteArray(64) { 7 }, ByteArray(12) { 5 })
        val decoded = Envelope.decode(original.encode())!!
        assertTrue(decoded.ttl > 0)
        assertEquals(original.packetId, decoded.packetId)
        assertEquals(EncryptionMode.AEAD_GROUP, decoded.encryption)
    }
}
