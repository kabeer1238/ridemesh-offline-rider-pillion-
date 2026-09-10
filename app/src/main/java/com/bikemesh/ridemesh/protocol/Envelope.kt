package com.bikemesh.ridemesh.protocol

import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * The single canonical RideMesh wire contract, shared by every transport.
 *
 * This is the hand-rolled binary encoding of `Envelope` from
 * `protocol/ridemesh.proto`. We keep it dependency-free (no protobuf runtime)
 * for the same reason [com.bikemesh.ridemesh.transport.InternetNode] hand-rolls
 * MQTT, but the field set and semantics deliberately match the proto so an iOS
 * client (or a protobuf migration later) stays byte-compatible.
 *
 * IMPORTANT — why the header is cleartext:
 * Routing/relay fields (ttl, hop_count, packet_id, origin, previous_hop) stay in
 * the clear so a relay can deduplicate and forward WITHOUT holding the group key.
 * Only [payload] is encrypted (see [com.bikemesh.ridemesh.crypto.RideCrypto]).
 * A relay mutates only the cleartext header via [forwardedBy]; it never touches
 * the ciphertext or the nonce, so downstream members still decrypt correctly.
 */
data class Envelope(
    val protocolVersion: Int,
    val packetId: UUID,
    val originNodeId: UUID,
    val previousHopNodeId: UUID,   // NONE_UUID when this is the origin
    val rideId: String,
    val destinationNodeId: UUID,   // NONE_UUID means group/broadcast
    val packetType: PacketType,
    val ttl: Int,
    val hopCount: Int,
    val sequence: Long,
    val timestampMs: Long,
    val priority: Priority,
    val flags: Int,
    val encryption: EncryptionMode,
    val keyEpoch: Int,
    val nonce: ByteArray,          // empty for ENCRYPTION_NONE, 12 bytes for AEAD
    val payload: ByteArray,        // plaintext if NONE, ciphertext+tag otherwise
) {

    /** Returns a copy prepared for relay: ttl-1, hop_count+1, previous_hop = me. */
    fun forwardedBy(relayNodeId: UUID): Envelope = copy(
        ttl = (ttl - 1).coerceAtLeast(0),
        hopCount = (hopCount + 1).coerceAtMost(MAX_U8),
        previousHopNodeId = relayNodeId,
    )

    fun encode(): ByteArray {
        val rideBytes = rideId.toByteArray(Charsets.UTF_8)
        require(rideBytes.size <= MAX_U8) { "rideId too long" }
        require(nonce.size <= MAX_U8) { "nonce too long" }

        val size = FIXED_PREFIX_BYTES + 1 + rideBytes.size + 1 + nonce.size + 4 + payload.size
        val buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN)

        buf.putInt(MAGIC)
        buf.put(protocolVersion.toU8())
        buf.put(packetType.value.toU8())
        buf.put(priority.value.toU8())
        buf.put(encryption.value.toU8())
        buf.put(ttl.coerceIn(0, MAX_U8).toByte())
        buf.put(hopCount.coerceIn(0, MAX_U8).toByte())
        buf.putShort(flags.toShort())
        buf.putInt(keyEpoch)
        buf.putLong(sequence)
        buf.putLong(timestampMs)
        buf.putUuid(packetId)
        buf.putUuid(originNodeId)
        buf.putUuid(previousHopNodeId)
        buf.putUuid(destinationNodeId)

        buf.put(rideBytes.size.toByte())
        buf.put(rideBytes)
        buf.put(nonce.size.toByte())
        buf.put(nonce)
        buf.putInt(payload.size)
        buf.put(payload)

        return buf.array()
    }

    // Data classes with ByteArray members need explicit equals/hashCode.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Envelope) return false
        return protocolVersion == other.protocolVersion &&
            packetId == other.packetId &&
            originNodeId == other.originNodeId &&
            previousHopNodeId == other.previousHopNodeId &&
            rideId == other.rideId &&
            destinationNodeId == other.destinationNodeId &&
            packetType == other.packetType &&
            ttl == other.ttl &&
            hopCount == other.hopCount &&
            sequence == other.sequence &&
            timestampMs == other.timestampMs &&
            priority == other.priority &&
            flags == other.flags &&
            encryption == other.encryption &&
            keyEpoch == other.keyEpoch &&
            nonce.contentEquals(other.nonce) &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = packetId.hashCode()
        result = 31 * result + originNodeId.hashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        const val PROTOCOL_VERSION = 2
        const val MAX_U8 = 0xFF

        /** Sentinel meaning "no node" (no previous hop) or "broadcast" (no destination). */
        val NONE_UUID: UUID = UUID(0L, 0L)

        private const val MAGIC = 0x524D4532 // "RME2" = RideMesh Envelope v2

        // 4 magic + 1 ver + 1 type + 1 prio + 1 enc + 1 ttl + 1 hop + 2 flags
        // + 4 epoch + 8 seq + 8 ts + 16*4 uuids = 96
        private const val FIXED_PREFIX_BYTES = 96

        fun decode(bytes: ByteArray): Envelope? {
            if (bytes.size < FIXED_PREFIX_BYTES + 6) return null
            return try {
                val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
                if (buf.int != MAGIC) return null

                val version = buf.get().toU8Int()
                val type = PacketType.fromValue(buf.get().toU8Int()) ?: return null
                val priority = Priority.fromValue(buf.get().toU8Int())
                val encryption = EncryptionMode.fromValue(buf.get().toU8Int()) ?: return null
                val ttl = buf.get().toU8Int()
                val hopCount = buf.get().toU8Int()
                val flags = buf.short.toInt() and 0xFFFF
                val keyEpoch = buf.int
                val sequence = buf.long
                val timestampMs = buf.long
                val packetId = buf.getUuid()
                val origin = buf.getUuid()
                val previousHop = buf.getUuid()
                val destination = buf.getUuid()

                val rideLen = buf.get().toU8Int()
                val rideBytes = ByteArray(rideLen)
                buf.get(rideBytes)
                val rideId = rideBytes.toString(Charsets.UTF_8)

                val nonceLen = buf.get().toU8Int()
                val nonce = ByteArray(nonceLen)
                buf.get(nonce)

                val payloadLen = buf.int
                if (payloadLen < 0 || payloadLen > buf.remaining()) return null
                val payload = ByteArray(payloadLen)
                buf.get(payload)

                Envelope(
                    protocolVersion = version,
                    packetId = packetId,
                    originNodeId = origin,
                    previousHopNodeId = previousHop,
                    rideId = rideId,
                    destinationNodeId = destination,
                    packetType = type,
                    ttl = ttl,
                    hopCount = hopCount,
                    sequence = sequence,
                    timestampMs = timestampMs,
                    priority = priority,
                    flags = flags,
                    encryption = encryption,
                    keyEpoch = keyEpoch,
                    nonce = nonce,
                    payload = payload,
                )
            } catch (_: BufferUnderflowException) {
                null
            } catch (_: Throwable) {
                null
            }
        }

        private fun Int.toU8(): Byte = (this and 0xFF).toByte()
        private fun Byte.toU8Int(): Int = this.toInt() and 0xFF

        private fun ByteBuffer.putUuid(id: UUID): ByteBuffer {
            putLong(id.mostSignificantBits)
            putLong(id.leastSignificantBits)
            return this
        }

        private fun ByteBuffer.getUuid(): UUID = UUID(long, long)
    }
}
