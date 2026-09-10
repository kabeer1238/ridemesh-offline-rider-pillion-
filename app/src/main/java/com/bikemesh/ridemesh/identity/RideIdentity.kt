package com.bikemesh.ridemesh.identity

import android.content.Context
import java.util.UUID

/**
 * Stable, cross-transport rider/node identity.
 *
 * The V0.2 code generated a fresh [UUID] inside every transport class and on
 * every process start, so the same rider looked like a different node on the
 * lobby, the local mesh, and the Internet path — which makes presence and
 * duplicate-suppression impossible to correlate.
 *
 * RideMesh needs ONE node id per install that all transports share (roadmap
 * V0.3 "stable node / ride identity model"). This persists it once and reuses
 * it everywhere.
 */
class RideIdentity private constructor(val nodeId: UUID) {

    /** First 4 bytes of the node id, handy as a short display/debug tag. */
    fun shortTag(): String = nodeId.toString().take(8)

    companion object {
        private const val PREFS = "ridemesh_identity"
        private const val KEY_NODE_ID = "node_id"

        fun get(context: Context): RideIdentity {
            val prefs = context.applicationContext
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

            val existing = prefs.getString(KEY_NODE_ID, null)
            val id = if (existing != null) {
                runCatching { UUID.fromString(existing) }.getOrNull()
                    ?: newAndStore(prefs)
            } else {
                newAndStore(prefs)
            }
            return RideIdentity(id)
        }

        private fun newAndStore(
            prefs: android.content.SharedPreferences,
        ): UUID {
            val id = UUID.randomUUID()
            prefs.edit().putString(KEY_NODE_ID, id.toString()).apply()
            return id
        }
    }
}
