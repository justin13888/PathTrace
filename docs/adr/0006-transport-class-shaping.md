# 0006: Transport class shaping: QUIC header framing (header/1) and genuine TLS on tcp/443

- status: accepted
- date: 2026-10-10
- requirements: REQ-PRB-015, REQ-PRB-023, REQ-PRB-024, REQ-PRB-026
- evidence: —

## Context

Middleboxes treat traffic by appearance: port, protocol, and for some deep-packet inspection, the protocol's own handshake. The draft spec probes `udp/443 QUIC-shaped` and `tcp/443 TLS-shaped` classes without defining how faithful the shaping is.

## Options considered

QUIC-shaped UDP:
1. **Opaque payload on UDP/443**: already covered by the `udp/443 opaque` class.
2. **Valid QUIC v1 header framing** (long-header Initial-typed first packets, then short-header packets with the fixed bit set, consistent connection IDs) around authenticated opaque payload. This passes classifiers that check header structure. DPI that decrypts the Initial (keys derive from the DCID, RFC 9001 §5.2) would find no ClientHello.
3. **Cryptographically faithful Initial** containing a real TLS ClientHello CRYPTO frame. Needs QUIC Initial packet protection and TLS message construction. Highest fidelity, highest cost.

TLS-shaped TCP:
1. **TLS record framing without a handshake**: fails any middlebox that tracks the handshake.
2. **A real TLS 1.3 handshake** with synchronous rustls. The responder presents a self-signed certificate whose fingerprint is delivered over the Noise-authenticated control channel, so the probe still authenticates the server.

## Decision

QUIC: option 2 now, recorded as `quic_shape = "header/1"` in the flow table so that traces state their shaping fidelity. Option 3 is deferred (#14) and would be recorded as `initial/1`. TLS: option 2, a real handshake, because it costs little with rustls and removes a whole class of false "blocked" results.

## Consequences

- Policy results for the QUIC class are valid for header-based classification, but not for decrypting DPI. The trace says which applies.
- rustls (synchronous API) enters the dependency tree for the tcp/443 class only; ADR 0007 holds (no async runtime).
