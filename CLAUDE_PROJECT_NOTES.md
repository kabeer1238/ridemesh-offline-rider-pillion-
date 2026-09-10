# RideMesh — Claude project copy

This is a working copy of [kabeer1238/RideMesh](https://github.com/kabeer1238/RideMesh)
with the offline-mesh foundation added (unified `Envelope` wire format,
persistent node identity, payload-layer AES-GCM group encryption, and
router-level deduplication).

## What was added on top of the original

New files under `app/src/main/java/com/bikemesh/ridemesh/`:

- `identity/RideIdentity.kt` — persistent per-install node UUID shared by all transports
- `protocol/Envelope.kt` — canonical wire format (hand-rolled encoding of `ridemesh.proto`)
- `protocol/ProtocolEnums.kt` — PacketType / Priority / AudioCodec / EncryptionMode
- `protocol/AudioFrame.kt` — audio payload with a codec field (PCM16 now, Opus-ready)
- `crypto/RideCrypto.kt` — AES-256-GCM group encryption, key derived from ride code
- `mesh/MeshRouter.kt` — transport-independent dedup + relay policy
- `mesh/OfflineMeshNode.kt` — Nearby P2P_CLUSTER transport on the new format
- `app/src/test/.../protocol/EnvelopeTest.kt` — round-trip / relay / rejection tests

Integration steps are in `docs/OFFLINE_MESH_INTEGRATION.md`.

## Note on removed files

Prebuilt APKs under `dist/` and the top-level beta APK were removed from source
control — they are build outputs, not source. CI (`.github/workflows/build-apk.yml`)
regenerates them. `.gitignore` now excludes `*.apk`.

## Status

The new offline-mesh classes are wired to compile alongside the existing
`MeshNode`; they are not yet called from `MainActivity`. Follow the integration
doc to switch the local path over. Not production-ready: see the limitations
block in `RideCrypto.kt` before shipping.
