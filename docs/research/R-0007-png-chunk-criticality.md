# R-0007: PNG chunk criticality rule (analogy for PTF section flags)
- source: https://www.w3.org/TR/png-3/ (PNG Specification Third Edition, W3C Recommendation 24 June 2025), §5.4 Chunk naming conventions, §14.2 Behavior of PNG editors
- accessed: 2026-10-10
- claim-under-test: SPEC §7.2 compares the PTF section design to PNG chunks (critical/ancillary bit). Check the PNG rule.
- verdict: partially-confirmed. The analogy holds, but PTF is stricter than PNG and drops PNG's safe-to-copy property.
- applicability: Applicable to the design of the PTF container (§7.2). Only the reader and editor rules matter, not image semantics.
## Evidence
§5.4:
> Ancillary bit: first byte  0 (uppercase) = critical, 1 (lowercase) = ancillary.
> A decoder [...] upon encountering an unknown chunk type in which the ancillary bit is 0, shall indicate
> to the user that the image contains information it cannot safely interpret.
> A decoder encountering an unknown chunk type in which the ancillary bit is 1 can safely ignore the chunk

> Safe-to-copy bit: fourth byte [...] This bit defines the proper handling of unrecognized chunks in a datastream that is being modified.
> If the program has made any changes to critical chunks [...] unrecognized unsafe chunks shall not be copied

- PNG puts the property bits in bit 5 (ASCII case) of the 4-byte type name: ancillary, private, reserved, safe-to-copy. PTF uses a separate `flags(u16)` field.
- The PNG signature `89 50 4E 47 0D 0A 1A 0A` is what the PTF magic `89 50 54 46 0D 0A 1A 0A` copies.
- PNG's CRC covers type and data but not length (§5.3).
## Implications for PTF / probe
- The PTF rule "reject on unknown critical" is stricter than PNG's "indicate to the user". That is reasonable for an emulator: silently replaying a trace whose critical semantics are unknown would be wrong. The note in §7.2 should say this is intentional.
- **Add a safe-to-copy bit, or an equivalent.** PTF tools will edit traces (trim, splice, anonymise, re-derive). Unknown sections derived from series data, such as fidelity scores, fits or summaries, become stale after an edit. PNG's rule (drop unknown unsafe chunks after modifying critical data) maps directly onto this.
- The private/public distinction is useful for vendor extensions. A naming convention or a flag bit would avoid ID collisions in the type registry.
- PTF's separate flags field is clearer than case-encoding. No change needed. The `reserved` bits must be required to be zero for writers and ignored by readers, as PNG requires for its reserved bit.
