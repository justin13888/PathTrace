# REQ-FMT: PTF trace format

### REQ-FMT-001: Container framing
- status: met
- spec: §7.2
- evidence: EXP-0003-r5

A PTF file is an 8-byte magic, a version (major, minor), file flags, then a sequence of typed, length-prefixed sections, each protected by a CRC32C.

### REQ-FMT-002: Section criticality
- status: met
- spec: §7.2
- evidence: EXP-0003-r5, EXP-0004-r2

A reader rejects a file containing an unknown critical section, or a critical section using unknown flag bits, and skips unknown non-critical sections without error.

### REQ-FMT-003: Bounded compressed sections
- status: met
- spec: §7.2
- evidence: EXP-0003-r5, EXP-0004-r2

Section payloads may be zstd-compressed. Compressed payloads declare their uncompressed size, and readers enforce configurable caps so that a hostile file cannot exhaust memory.

### REQ-FMT-004: Deterministic CBOR metadata with a schema
- status: met
- spec: §7.2
- evidence: EXP-0004-r2

Metadata is CBOR in a documented deterministic profile, with a published CDDL schema for every defined section.

### REQ-FMT-005: Self-describing columnar tables
- status: met
- spec: §7.2
- evidence: EXP-0003-r5, EXP-0001-r3

Bulk data is stored as tables whose column directory names each column's type, encoding, unit, clock domain, nullability and privacy class. Readers skip unknown columns.

### REQ-FMT-006: Raw layer is lossless and uncorrected
- status: met
- spec: §7.1
- evidence: EXP-0004-r2

Raw observations are integers (ns, bytes, bit/s) recorded in the clock domain they were measured in, never corrected in place. Clock corrections are derived data.

### REQ-FMT-007: Unknown and lost are explicit
- status: met
- spec: §7.1, §6.5
- evidence: EXP-0004-r2

Absence is represented by validity bitmaps and explicit `unknown` status, never by sentinel values. Capacity segments carry a quality of `saturated`, `estimated` or `unknown`.

### REQ-FMT-008: Provenance
- status: met
- spec: §7.1, §7.5
- evidence: EXP-0007-r8

META records the producing tool's version and git commit. Every derived parameter records its method as a versioned name (`name/N`), a confidence in [0, 1], and the raw data range it was derived from.

### REQ-FMT-009: Versioning rules
- status: met
- spec: §7.5
- evidence: EXP-0003-r5

Minor versions only add (sections, columns, keys). Major versions change the meaning of a critical section. Readers reject files with a higher major version and accept any minor.

### REQ-FMT-010: Permanent backward compatibility
- status: met
- spec: new
- evidence: EXP-0003-r5

Every PTF file of version 1.0 or later remains readable by every later release. Golden files from every release are kept in the conformance corpus and tested on every change.

### REQ-FMT-011: Crash-safe observation logs
- status: met
- spec: new
- evidence: EXP-0004-r2

Observation logs are written append-only in time-bounded chunks. After a crash or truncation at any byte offset, a reader recovers every complete chunk.

### REQ-FMT-012: Canonical encoding and content digest
- status: met
- spec: new
- evidence: EXP-0004-r2

Encoding the same content twice with the same tool version yields identical bytes. A content digest computed over the uncompressed canonical section payloads identifies a trace independently of compression settings.

### REQ-FMT-013: Whole-file integrity
- status: met
- spec: §7.3
- evidence: EXP-0003-r5

An optional final INDX section records section offsets, the BLAKE3 of all preceding bytes, and the content digest.

### REQ-FMT-014: Lossless text twin
- status: met
- spec: §7.1
- evidence: EXP-0003-r5, EXP-0004-r2

`pathtrace trace dump` writes JSON Lines and `pathtrace trace load` reads them back to a byte-identical canonical PTF file, including for sections and columns unknown to the tool.

### REQ-FMT-015: Space budget
- status: met
- spec: new
- evidence: EXP-0002-r14, EXP-0001-r3

In `standard` and `deep` sessions, where the volume is, the raw per-packet layer costs at most 8 bytes per packet after compression, and a `standard` session at up to 100 Mbit/s produces a file of at most 10 MB. `smoke` and `light` sessions are small in absolute terms (about 100 kB). Their fixed overhead dominates, so they are exempt from the per-packet figure, though it is still measured and reported in the ground-truth evidence.

### REQ-FMT-016: Safe parsing of untrusted files
- status: met
- spec: §2.3, §13.3
- evidence: EXP-0005-r6

The reader never panics, never recurses without bound and keeps memory bounded on arbitrary input. It is fuzzed continuously.

### REQ-FMT-017: Privacy by construction
- status: met
- spec: §7.6
- evidence: EXP-0004-r2

Every identifying value is marked with a privacy class (`id` or `quasi`) where it is stored. `trace redact --level shareable` removes `id` data and `--level anonymous` also removes `quasi` data and shifts wall-clock domains, without per-field code. The level applied is recorded in META.

### REQ-FMT-018: Conformance suite
- status: met
- spec: §7.8
- evidence: EXP-0003-r5

A corpus of valid and invalid files with expected verdicts and a reference validator (`pathtrace trace check`) let an independent implementation prove conformance. An independent reader written only from the specification passes it.

### REQ-FMT-019: Section inventory
- status: met
- spec: §7.3
- evidence: EXP-0004-r2

PTF 1.0 defines META, FLOW, CLOK, OBSV, CTXS, EVNT (raw layer), PATH, SERS, PLCY, VALD (derived layer) and INDX.

### REQ-FMT-020: Path model fields
- status: met
- spec: §7.4
- evidence: EXP-0002-r14

PATH holds, per direction, capacity (delivery opportunities or rate segments with quality), light-flow capacity, base delay with its split method, jitter (series and fitted model), loss (events and Gilbert-Elliott fit with intervals), queue (depth in bytes and time, discipline hint), policer per class, reordering, duplication, path MTU with black-hole flag, and ECN/DSCP handling, each with method and confidence.

### REQ-FMT-021: Interoperability exports and imports
- status: met
- spec: §7.7
- evidence: EXP-0002-r14, EXP-0006-r7

Mahimahi traces can be imported (capacity only, all other fields `unknown`) and exported (uplink and downlink traces plus delay and loss arguments); a netem command line can be exported from a trace's static summary.

### REQ-FMT-022: Sufficient for the simulator
- status: met
- spec: new
- design: docs/design/simulator-requirements.md
- evidence: EXP-0002-r14

PTF carries every input the anticipated simulator pipeline stages need, demonstrated by recovering known ground-truth impairments from probe captures and by reproducing a trace after replay through an independent emulator.

### REQ-FMT-023: Rattan export
- status: deferred
- spec: §7.7
- issue: #11

Export a trace to a Rattan channel configuration.

### REQ-FMT-024: Signed traces
- status: deferred
- spec: §7.3
- issue: #12

An optional SIGN section carries an Ed25519 signature over the content digest.

### REQ-FMT-025: pcapng import
- status: deferred
- spec: §7.7
- issue: #13

A pair of pcapng captures (one per end) can be imported as observations and then derived.
