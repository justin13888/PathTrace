# references/

Third-party material the project depends on for testing or validation (e.g. public Mahimahi traces used as import fixtures). Not our code.

Rules:

- Only material whose license permits redistribution is committed. Anything else is referenced by URL and fetched by a script, never vendored.
- Every item is listed below with source URL, retrieval date, license, and BLAKE3 hash. `cargo xtask audit` does not check these hashes automatically yet; verify with `b3sum`.
- Never modify an item in place. A newer version is a new entry.
- Commit scope: `research` (e.g. `docs(research): add mahimahi verizon trace fixture`).

| Path | Source | Retrieved | License | BLAKE3 |
|---|---|---|---|---|
