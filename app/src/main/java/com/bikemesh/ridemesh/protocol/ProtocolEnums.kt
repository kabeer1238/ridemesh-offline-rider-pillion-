package com.bikemesh.ridemesh.protocol

/**
 * Wire enums, kept numerically identical to `protocol/ridemesh.proto` so the
 * hand-rolled Android encoding stays compatible with any generated client.
 */

enum class PacketType(val value: Int) {
    UNSPECIFIED(0),
    AUDIO(1),
    PRESENCE(2),
    CONTROL(3),
    ACK(4),
    ROUTE(5),
    SOS(6),
    KEY(7);

    companion object {
        fun fromValue(v: Int): PacketType? = entries.firstOrNull { it.value == v }
    }
}

enum class Priority(val value: Int) {
    NORMAL(0),
    HIGH(1),
    CRITICAL(2);

    companion object {
        fun fromValue(v: Int): Priority = entries.firstOrNull { it.value == v } ?: NORMAL
    }
}

enum class AudioCodec(val value: Int) {
    PCM16(0),
    OPUS(1);

    companion object {
        fun fromValue(v: Int): AudioCodec = entries.firstOrNull { it.value == v } ?: PCM16
    }
}

enum class EncryptionMode(val value: Int) {
    NONE(0),
    AEAD_GROUP(1);

    companion object {
        fun fromValue(v: Int): EncryptionMode? = entries.firstOrNull { it.value == v }
    }
}
