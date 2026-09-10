# RideMesh offline mesh — integration guide

This drop implements the **offline local mesh** on the unified `Envelope` wire
format, with a persistent node identity, payload-layer AES-GCM group encryption,
and router-level deduplication. It's the offline half of what we discussed —
recommendations #1 (unified envelope), #2 (stable identity), #5 (encryption),
and the dedup part of #4.

Everything here is verified: 32 round-trip / crypto / relay / dedup checks pass
on the JVM, including the full capture→seal→encode→decode→open→play path.

## Files

Copy into `app/src/main/java/com/bikemesh/ridemesh/`:

```
identity/RideIdentity.kt        persistent per-install node UUID
protocol/Envelope.kt            canonical wire format (matches ridemesh.proto)
protocol/ProtocolEnums.kt       PacketType / Priority / AudioCodec / EncryptionMode
protocol/AudioFrame.kt          the audio payload (codec/rate/channels + PCM)
crypto/RideCrypto.kt            AES-256-GCM group key derived from the ride code
mesh/MeshRouter.kt              transport-independent dedup + relay policy
mesh/OfflineMeshNode.kt         Nearby P2P_CLUSTER transport using all of the above
```

Copy into `app/src/test/java/com/bikemesh/ridemesh/`:

```
protocol/EnvelopeTest.kt        round-trip + relay + rejection tests
```

No new Gradle dependencies. AES-GCM and PBKDF2 are in the platform (`javax.crypto`),
and you already have `play-services-nearby`.

## How it replaces the old `MeshNode`

`OfflineMeshNode` is a drop-in for `MeshNode` with three constructor additions
(identity, router, crypto) and slightly renamed callbacks. The audio pipeline,
VAD, wind filter, and routing UI are untouched — this only swaps the wire format
and adds encryption.

### 1. Create the shared, long-lived pieces once (in MainActivity.onCreate)

```kotlin
private lateinit var identity: RideIdentity
private lateinit var router: MeshRouter
private lateinit var crypto: RideCrypto
private lateinit var offlineMesh: OfflineMeshNode

// ...in onCreate, before starting a ride:
identity = RideIdentity.get(applicationContext)
router   = MeshRouter(identity.nodeId)     // outlives every mesh restart
crypto   = RideCrypto()

offlineMesh = OfflineMeshNode(
    context = applicationContext,
    localNodeId = identity.nodeId,          // same id across all transports
    router = router,
    crypto = crypto,
    listener = object : OfflineMeshNode.Listener {
        override fun onLog(message: String) = log(message)
        override fun onDirectPeerCount(count: Int) { directPeerCount = count; /* update UI */ }
        override fun onAudioReceived(pcm: ByteArray) {
            if (rideStarted) audioEngine.playIncoming(pcm)
        }
    },
    // encryptPayload = false  // <-- set false ONLY for the A-B-C bench proof
)
```

Note the `MeshRouter` and `RideIdentity` are created **once** and reused; do NOT
recreate them on every `start()`. That's the fix for dedup state being wiped on
reconnect refresh.

### 2. Start / stop follow the same shape as before

```kotlin
offlineMesh.start(
    riderName = binding.riderName.text?.toString().orEmpty(),
    rideCode  = normalizedRideCode(),
    keyEpoch  = 0,                          // bump later for key rotation
    labRole   = OfflineMeshNode.LabRole.NORMAL,
)
// ...
offlineMesh.stop()
```

### 3. Feed captured audio in

Your `AudioEngine` already calls `onCapturedFrame`. Point it here:

```kotlin
private fun sendHybridAudio(pcm: ByteArray) {
    if (!rideStarted || pcm.isEmpty()) return
    // (keep your internet-first logic; the offline call just changes name)
    offlineMesh.sendAudioFrame(pcm)
}
```

`sendAudioFrame` wraps the PCM in an `AudioFrame`, encrypts it, builds an AUDIO
`Envelope`, marks its own packet id in the router (so an echo is dropped), and
floods it to all connected peers.

## What each piece does

- **Header is cleartext, payload is encrypted.** A relay reads `ttl`, `packetId`,
  `origin` to dedup and forward without ever holding the group key. Only the
  `AudioFrame` bytes are sealed. `forwardedBy()` mutates only the header and
  re-emits the *same* ciphertext + nonce, so downstream members still decrypt.

- **Dedup is global and durable.** `MeshRouter.acceptOnce(packetId)` returns true
  only the first time. Because the router is owned above the transport, a mesh
  restart no longer lets in-flight packets loop back through.

- **Encryption is a real first pass, not production membership.** The group key
  is PBKDF2-derived from the ride code, so a passive listener on any shared
  medium can't hear the ride. But anyone who knows the code can derive the key —
  this is privacy, not access control. `RideCrypto.kt` documents the three known
  limitations (shared static key, random-nonce budget, no replay check) and the
  V1.0 path. Read that block before shipping.

## The bench (A-B-C) proof still works

Set `encryptPayload = false` and pass `labRole = A / B / C` on three phones. The
`LabRole` filter forces A↔B and B↔C links only, so a packet from A reaches C only
by B relaying it — proving multi-hop over the new envelope. Watch the logs for
`hopCount` climbing. Flip `encryptPayload = true` once the topology is proven.

## What this deliberately does NOT do yet

- **No Opus.** `AudioFrame` carries a `codec` field and the decoder skips unknown
  codecs gracefully, so PCM16 and a future OPUS build interoperate without
  crashing — but the encoder still emits PCM16. Opus is the next big lever
  (roadmap V0.5) and the single biggest thing standing between this and a
  multi-hop field test with more than ~3 phones.
- **No gateway bridge yet.** But because the offline mesh and the Internet path
  can now speak the *same* `Envelope`, a bridge becomes "forward the decoded
  envelope to the other transport" instead of a transcode. That's the next piece
  I'd build after Opus — the InternetNode migration onto `Envelope`.
- **No warm dual-path.** Still a hard cutover in `sendHybridAudio`. Unifying the
  format is the prerequisite for fixing that; the routing change comes after.
