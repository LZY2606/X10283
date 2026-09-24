package quiccourt.model;

/** Immutable evidence kinds. Raw bytes, truncated packet numbers, header-protection
 *  candidates, key generations, CID events, paths and ACK ranges are all preserved. */
public enum MaterialKind {
    DATAGRAM,              // raw datagram bytes (hex), direction, path, arrival time
    PACKET_HEADER,         // parsed header: space, truncated pn, pn length, key phase bit
    HP_CANDIDATE,          // header-protection removal candidate referencing a key generation
    KEY_GENERATION,        // a secret generation: suite, generation index, valid-from
    DECRYPTION_CANDIDATE,  // attempted decrypt of a header under a key generation
    CID_EVENT,             // connection-id issued / retired / selected
    PATH_EVENT,            // path observed / migrated / validated
    ACK_RANGE              // ack range block for a packet-number space on a path
}
