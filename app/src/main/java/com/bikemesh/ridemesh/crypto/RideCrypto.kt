package com.bikemesh.ridemesh.crypto

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Payload-layer group encryption for RideMesh.
 *
 * Design goals from the architecture review:
 *  - Encrypt ABOVE the transport so relay phones forward ciphertext and never
 *    need the plaintext (they don't hold... well, in a closed ride every relay
 *    is a member so they do hold the key, but the envelope header stays
 *    cleartext so relaying never requires a decrypt).
 *  - One symmetric group key per (rideId, keyEpoch), derived from the ride code.
 *    keyEpoch lets a future membership change rotate keys without a new ride.
 *
 * This is a pragmatic V0.4 first pass: a ride-code-derived pre-shared key. It is
 * a real improvement over the current cleartext audio, but it is NOT full
 * authenticated membership with per-member keys — that's the V1.0 target. See
 * the notes at the bottom for the known limitations before you ship this.
 *
 * AEAD: AES-256-GCM, 96-bit nonce, 128-bit tag. The nonce is generated per
 * message and travels in the envelope, so the receiver needs only the derived
 * key to decrypt.
 */
class RideCrypto {

    private val random = SecureRandom()
    private val keyCache = ConcurrentHashMap<String, SecretKey>()

    data class Sealed(val nonce: ByteArray, val ciphertext: ByteArray)

    /**
     * Encrypts [plaintext] under the group key for (rideCode, keyEpoch).
     * Returns the fresh nonce plus ciphertext-with-tag.
     */
    fun seal(rideCode: String, keyEpoch: Int, plaintext: ByteArray): Sealed {
        val key = groupKey(rideCode, keyEpoch)
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        return Sealed(nonce, ciphertext)
    }

    /**
     * Decrypts under the group key for (rideCode, keyEpoch).
     * Returns null on any failure, including a bad auth tag (wrong key / tampered
     * packet / not actually a ride member). Callers must treat null as "drop it".
     */
    fun open(
        rideCode: String,
        keyEpoch: Int,
        nonce: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? {
        if (nonce.size != NONCE_BYTES) return null
        return try {
            val key = groupKey(rideCode, keyEpoch)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
            cipher.doFinal(ciphertext)
        } catch (_: Throwable) {
            // AEADBadTagException and friends land here. Never leak which.
            null
        }
    }

    private fun groupKey(rideCode: String, keyEpoch: Int): SecretKey {
        val normalized = rideCode.trim().uppercase()
        return keyCache.getOrPut("$normalized#$keyEpoch") {
            deriveKey(normalized, keyEpoch)
        }
    }

    private fun deriveKey(rideCode: String, keyEpoch: Int): SecretKey {
        // Salt binds the key to the app + the epoch so the same ride code yields
        // a different key each epoch, and so the code alone (without the app
        // salt) can't be brute-forced against generic rainbow tables.
        val salt = APP_SALT + intToBytes(keyEpoch)
        val spec = PBEKeySpec(rideCode.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun intToBytes(v: Int): ByteArray = byteArrayOf(
        (v ushr 24).toByte(),
        (v ushr 16).toByte(),
        (v ushr 8).toByte(),
        v.toByte(),
    )

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
        private const val KEY_BITS = 256
        private const val TAG_BITS = 128
        private const val NONCE_BYTES = 12
        private const val PBKDF2_ITERATIONS = 120_000

        // Fixed application salt. Changing this invalidates all derived keys, so
        // treat it as a protocol constant, not a secret. Regenerate ONCE if you
        // ever want a hard break with older builds.
        private val APP_SALT = byteArrayOf(
            0x52, 0x69, 0x64, 0x65, 0x4D, 0x65, 0x73, 0x68,
            0x2D, 0x76, 0x31, 0x2D, 0x73, 0x61, 0x6C, 0x74,
        )
    }

    /*
     * KNOWN LIMITATIONS — read before shipping to real riders:
     *
     * 1. Shared static key. Everyone who knows the 6-char ride code can derive
     *    the key, decrypt, AND encrypt. There is no per-rider authentication, so
     *    a code leak = full compromise of that ride. Fine for privacy from a
     *    passive eavesdropper on a public relay; NOT fine as membership control.
     *
     * 2. Random 96-bit nonces under a shared key. NIST SP 800-38D bounds random
     *    GCM nonces at ~2^32 encryptions per key before collision risk matters.
     *    Audio at ~50 packets/s reaches that in years, but ALL senders share the
     *    key, so budget is shared. Mitigate by rotating keyEpoch periodically.
     *    Hardening path: switch to deterministic nonce = senderPrefix||counter.
     *
     * 3. No replay protection here. The mesh dedup (packetId) stops loop replays,
     *    but a captured ciphertext replayed into a fresh ride is not rejected by
     *    this layer. Add a monotonic-sequence check keyed by origin when you add
     *    the KEY/ROUTE packet handling.
     *
     * The V1.0 target remains authenticated ride membership with key epochs and
     * per-member keys; this class is the interface those will slot behind.
     */
}
