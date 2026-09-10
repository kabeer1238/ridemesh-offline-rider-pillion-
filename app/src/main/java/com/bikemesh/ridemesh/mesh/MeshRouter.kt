package com.bikemesh.ridemesh.mesh

import com.bikemesh.ridemesh.protocol.Envelope
import java.util.Collections
import java.util.LinkedHashMap
import java.util.UUID

/**
 * Transport-independent routing brain.
 *
 * The V0.2 code kept the "seen packets" set INSIDE MeshNode, so every mesh
 * restart (which happens on every reconnect refresh) wiped dedup state and let
 * in-flight packets loop back through once. The router is meant to outlive any
 * single transport instance: create ONE and hold it in MainActivity / the ride
 * service, then hand the same instance to the offline mesh, and later to the
 * Internet transport too, so a packet that arrives over two paths during a
 * hybrid handoff is de-duplicated globally.
 *
 * It owns two policy decisions and nothing platform-specific:
 *   1. Have I already processed this packetId?  (loop / duplicate suppression)
 *   2. Should this packet still be relayed?      (ttl / origin checks)
 */
class MeshRouter(
    private val localNodeId: UUID,
    seenCapacity: Int = DEFAULT_SEEN_CAPACITY,
) {

    // Access-ordered LRU of packet ids we've already accepted. Bounded so a long
    // ride doesn't grow it without limit.
    private val seen: MutableMap<UUID, Boolean> = Collections.synchronizedMap(
        object : LinkedHashMap<UUID, Boolean>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<UUID, Boolean>?): Boolean =
                size > seenCapacity
        }
    )

    /**
     * Marks [packetId] as seen and returns true only the FIRST time.
     * Call this once per received (or locally originated) packet. A false result
     * means "duplicate — drop it, do not play, do not relay".
     */
    fun acceptOnce(packetId: UUID): Boolean {
        synchronized(seen) {
            if (seen.containsKey(packetId)) return false
            seen[packetId] = true
            return true
        }
    }

    /** True if a just-accepted packet should be forwarded to other peers. */
    fun shouldRelay(envelope: Envelope): Boolean = envelope.ttl > 0

    /** True if this packet's audio is meant for us to play (not our own echo). */
    fun isForLocalPlayback(envelope: Envelope): Boolean =
        envelope.originNodeId != localNodeId

    fun reset() {
        synchronized(seen) { seen.clear() }
    }

    companion object {
        private const val DEFAULT_SEEN_CAPACITY = 4096
    }
}
