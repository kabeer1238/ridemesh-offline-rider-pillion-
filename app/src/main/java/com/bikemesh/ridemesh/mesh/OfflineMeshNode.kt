package com.bikemesh.ridemesh.mesh

import android.content.Context
import com.bikemesh.ridemesh.crypto.RideCrypto
import com.bikemesh.ridemesh.protocol.AudioCodec
import com.bikemesh.ridemesh.protocol.AudioFrame
import com.bikemesh.ridemesh.protocol.Envelope
import com.bikemesh.ridemesh.protocol.EncryptionMode
import com.bikemesh.ridemesh.protocol.PacketType
import com.bikemesh.ridemesh.protocol.Priority
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionOptions
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionType
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * RideMesh OFFLINE transport.
 *
 * No Internet, no broker: Google Nearby Connections (P2P_CLUSTER) gives us
 * multiple simultaneous direct nearby links over BLE / Bluetooth / Wi-Fi, and
 * RideMesh adds app-level multi-hop by TTL-flooding [Envelope]s and relaying
 * anything still alive. This is the "local multi-hop path" from the architecture
 * doc, rebuilt on the shared wire format with payload encryption.
 *
 * What changed vs the V0.2 MeshNode:
 *   - Emits/parses the canonical [Envelope] (not the old RMV1 format), so an
 *     Internet gateway can forward the SAME logical packet without transcoding.
 *   - Uses a STABLE node id (passed in), shared across all transports.
 *   - Encrypts the audio payload with [RideCrypto] (AES-GCM group key). Relays
 *     forward ciphertext untouched; only members with the ride key can hear it.
 *   - Dedup lives in the shared [MeshRouter], so a mesh restart no longer wipes
 *     loop-suppression state.
 *
 * The audio pipeline (VAD, wind filter, playback) is unchanged — this node just
 * takes captured PCM frames in [sendAudioFrame] and hands decoded PCM back via
 * [Listener.onAudioReceived].
 */
class OfflineMeshNode(
    context: Context,
    private val localNodeId: UUID,
    private val router: MeshRouter,
    private val crypto: RideCrypto,
    private val listener: Listener,
    /** Set false to run the A-B-C bench proof without keys (cleartext payload). */
    private val encryptPayload: Boolean = true,
) {

    /** Forced topology for bench testing multi-hop; NORMAL connects to everyone. */
    enum class LabRole { NORMAL, A, B, C }

    interface Listener {
        fun onLog(message: String)
        fun onDirectPeerCount(count: Int)
        /** Decoded PCM ready to play. */
        fun onAudioReceived(pcm: ByteArray)
    }

    private val client: ConnectionsClient = Nearby.getConnectionsClient(context)
    private val sequence = AtomicLong(0L)

    private val connected = ConcurrentHashMap.newKeySet<String>()
    private val requested = ConcurrentHashMap.newKeySet<String>()
    private val endpointNames = ConcurrentHashMap<String, String>()

    private var riderName: String = "Rider"
    private var rideCode: String = "RIDE01"
    private var keyEpoch: Int = 0
    private var labRole: LabRole = LabRole.NORMAL
    @Volatile private var running = false

    // ---- Nearby callbacks ---------------------------------------------------

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            try {
                if (payload.type != Payload.Type.BYTES) return
                val raw = payload.asBytes() ?: return
                val envelope = Envelope.decode(raw) ?: return

                // Ignore traffic from other rides that happens to reach us.
                if (!envelope.rideId.equals(rideCode, ignoreCase = true)) return

                // Global dedup: first sighting only.
                if (!router.acceptOnce(envelope.packetId)) return

                // Deliver audio meant for us (never our own echo).
                if (envelope.packetType == PacketType.AUDIO &&
                    router.isForLocalPlayback(envelope)
                ) {
                    decodeAudio(envelope)?.let { listener.onAudioReceived(it) }
                }

                // Multi-hop relay: forward ciphertext untouched, header decremented.
                if (router.shouldRelay(envelope)) {
                    relay(envelope.forwardedBy(localNodeId), excludeEndpoint = endpointId)
                }
            } catch (t: Throwable) {
                listener.onLog("Payload error: ${t.short()}")
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) = Unit
    }

    private val lifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            endpointNames[endpointId] = info.endpointName
            val remoteCode = parseRideCode(info.endpointName)
            val remoteRole = parseLabRole(info.endpointName)
            try {
                if (remoteCode == rideCode && isAllowedPeer(remoteRole)) {
                    client.acceptConnection(endpointId, payloadCallback)
                    listener.onLog("Pairing with ${displayName(info.endpointName)}")
                } else {
                    client.rejectConnection(endpointId)
                }
            } catch (t: Throwable) {
                listener.onLog("Pairing error: ${t.short()}")
            }
        }

        override fun onConnectionResult(endpointId: String, resolution: ConnectionResolution) {
            requested.remove(endpointId)
            if (resolution.status.isSuccess) {
                connected.add(endpointId)
                listener.onLog("Connected: ${displayName(endpointNames[endpointId] ?: endpointId)}")
            } else {
                listener.onLog("Connection failed: ${resolution.status.statusCode}")
            }
            listener.onDirectPeerCount(connected.size)
        }

        override fun onDisconnected(endpointId: String) {
            connected.remove(endpointId)
            requested.remove(endpointId)
            listener.onLog("Peer disconnected: ${displayName(endpointNames[endpointId] ?: endpointId)}")
            listener.onDirectPeerCount(connected.size)
        }
    }

    private val discoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            endpointNames[endpointId] = info.endpointName
            if (!running || parseRideCode(info.endpointName) != rideCode) return
            if (!isAllowedPeer(parseLabRole(info.endpointName))) return
            if (connected.contains(endpointId) || !requested.add(endpointId)) return

            listener.onLog("Found ${displayName(info.endpointName)} — connecting")
            try {
                client.requestConnection(
                    advertisedName(),
                    endpointId,
                    lifecycleCallback,
                    ConnectionOptions.Builder()
                        .setConnectionType(ConnectionType.NON_DISRUPTIVE)
                        .build(),
                ).addOnFailureListener {
                    requested.remove(endpointId)
                    listener.onLog("Could not connect to ${displayName(info.endpointName)}: ${it.message ?: "error"}")
                }
            } catch (t: Throwable) {
                requested.remove(endpointId)
                listener.onLog("Connection request error: ${t.short()}")
            }
        }

        override fun onEndpointLost(endpointId: String) {
            requested.remove(endpointId)
        }
    }

    // ---- Lifecycle ----------------------------------------------------------

    fun start(
        riderName: String,
        rideCode: String,
        keyEpoch: Int = 0,
        labRole: LabRole = LabRole.NORMAL,
    ) {
        stop()
        this.riderName = riderName.trim().ifBlank { "Rider" }.take(18)
        this.rideCode = rideCode.trim().uppercase().ifBlank { "RIDE01" }.take(12)
        this.keyEpoch = keyEpoch
        this.labRole = labRole
        running = true
        listener.onLog("Starting offline mesh for ride ${this.rideCode}")

        val advertising = AdvertisingOptions.Builder()
            .setStrategy(STRATEGY)
            .setConnectionType(ConnectionType.NON_DISRUPTIVE)
            .build()
        val discovery = DiscoveryOptions.Builder()
            .setStrategy(STRATEGY)
            .build()

        try {
            client.startAdvertising(advertisedName(), SERVICE_ID, lifecycleCallback, advertising)
                .addOnSuccessListener { listener.onLog("Offline mesh visible as ${this.riderName}") }
                .addOnFailureListener { listener.onLog("Advertising error: ${it.short()}") }

            client.startDiscovery(SERVICE_ID, discoveryCallback, discovery)
                .addOnSuccessListener { listener.onLog("Searching for nearby RideMesh riders") }
                .addOnFailureListener { listener.onLog("Discovery error: ${it.short()}") }
        } catch (t: Throwable) {
            running = false
            listener.onLog("Nearby start error: ${t.short()}")
        }
    }

    fun stop() {
        running = false
        runCatching { client.stopAdvertising() }
        runCatching { client.stopDiscovery() }
        runCatching { client.stopAllEndpoints() }
        connected.clear()
        requested.clear()
        endpointNames.clear()
        listener.onDirectPeerCount(0)
    }

    fun connectedPeerCount(): Int = connected.size

    // ---- Send / relay -------------------------------------------------------

    /**
     * Wrap one captured PCM frame in an encrypted AUDIO envelope and flood it.
     * Called from the audio engine's onCapturedFrame callback.
     */
    fun sendAudioFrame(pcm: ByteArray) {
        if (!running || pcm.isEmpty() || connected.isEmpty()) return

        val frame = AudioFrame(
            codec = AudioCodec.PCM16,
            sampleRateHz = SAMPLE_RATE,
            channels = 1,
            frameDurationMs = FRAME_MS,
            audio = pcm,
        ).encode()

        val envelope = buildAudioEnvelope(frame) ?: return

        // Pre-mark our own packet so it's dropped if it loops back to us.
        router.acceptOnce(envelope.packetId)
        relay(envelope, excludeEndpoint = null)
    }

    private fun buildAudioEnvelope(plaintextFrame: ByteArray): Envelope? {
        val nonce: ByteArray
        val payload: ByteArray
        val mode: EncryptionMode

        if (encryptPayload) {
            val sealed = try {
                crypto.seal(rideCode, keyEpoch, plaintextFrame)
            } catch (t: Throwable) {
                listener.onLog("Encrypt error: ${t.short()}")
                return null
            }
            nonce = sealed.nonce
            payload = sealed.ciphertext
            mode = EncryptionMode.AEAD_GROUP
        } else {
            nonce = ByteArray(0)
            payload = plaintextFrame
            mode = EncryptionMode.NONE
        }

        return Envelope(
            protocolVersion = Envelope.PROTOCOL_VERSION,
            packetId = UUID.randomUUID(),
            originNodeId = localNodeId,
            previousHopNodeId = localNodeId,
            rideId = rideCode,
            destinationNodeId = Envelope.NONE_UUID, // broadcast to the ride
            packetType = PacketType.AUDIO,
            ttl = MAX_TTL,
            hopCount = 0,
            sequence = sequence.incrementAndGet(),
            timestampMs = System.currentTimeMillis(),
            priority = Priority.NORMAL,
            flags = 0,
            encryption = mode,
            keyEpoch = keyEpoch,
            nonce = nonce,
            payload = payload,
        )
    }

    private fun decodeAudio(envelope: Envelope): ByteArray? {
        val frameBytes = when (envelope.encryption) {
            EncryptionMode.NONE -> envelope.payload
            EncryptionMode.AEAD_GROUP -> crypto.open(
                rideCode = rideCode,
                keyEpoch = envelope.keyEpoch,
                nonce = envelope.nonce,
                ciphertext = envelope.payload,
            ) ?: return null // wrong key / tampered — silently drop
        }
        val frame = AudioFrame.decode(frameBytes) ?: return null
        // Only PCM16 is decodable today; OPUS frames are recognised but skipped
        // until the V0.5 decoder lands, so a mixed-version ride won't crash.
        return if (frame.codec == AudioCodec.PCM16) frame.audio else null
    }

    private fun relay(envelope: Envelope, excludeEndpoint: String?) {
        val bytes = envelope.encode()
        for (endpoint in connected) {
            if (endpoint == excludeEndpoint) continue
            try {
                client.sendPayload(endpoint, Payload.fromBytes(bytes))
                    .addOnFailureListener { listener.onLog("Send error: ${it.short()}") }
            } catch (t: Throwable) {
                listener.onLog("Send error: ${t.short()}")
            }
        }
    }

    // ---- Advertised-name codec (ride|name|role|shortid) ----------------------

    private fun advertisedName(): String =
        "$rideCode|$riderName|${labRole.name}|${localNodeId.toString().take(8)}"

    private fun parseRideCode(endpointName: String): String =
        endpointName.substringBefore('|').uppercase()

    private fun parseLabRole(endpointName: String): LabRole {
        val parts = endpointName.split('|')
        return if (parts.size >= 3) {
            runCatching { LabRole.valueOf(parts[2].uppercase()) }.getOrDefault(LabRole.NORMAL)
        } else LabRole.NORMAL
    }

    private fun isAllowedPeer(remote: LabRole): Boolean {
        if (labRole == LabRole.NORMAL) return true
        return when (labRole) {
            LabRole.A -> remote == LabRole.B
            LabRole.B -> remote == LabRole.A || remote == LabRole.C
            LabRole.C -> remote == LabRole.B
            LabRole.NORMAL -> true
        }
    }

    private fun displayName(endpointName: String): String {
        val parts = endpointName.split('|')
        val name = if (parts.size >= 2) parts[1] else endpointName
        val role = parseLabRole(endpointName)
        return if (role == LabRole.NORMAL) name else "$name [${role.name}]"
    }

    private fun Throwable.short(): String = "${javaClass.simpleName}: ${message ?: "unknown"}"

    companion object {
        private const val SERVICE_ID = "com.bikemesh.ridemesh.voice"
        private val STRATEGY = Strategy.P2P_CLUSTER
        private const val MAX_TTL = 4

        // Kept in sync with AudioEngine's capture format.
        private const val SAMPLE_RATE = 16_000
        private const val FRAME_MS = 20
    }
}
