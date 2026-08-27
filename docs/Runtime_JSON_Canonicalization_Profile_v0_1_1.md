# Runtime JSON Canonicalization Profile v0.1.1

**Scope:** runtime-integrity candidate JSON and corpus-passport source hashing only

**Authority:** development test profile; it creates no runtime permission

## JSON domain

Every JSON hash produced or verified by the runtime-integrity validator uses the UTF-8 bytes emitted by RFC 8785 JSON Canonicalization Scheme (JCS), domain label `RFC8785_JCS_SHA256_V1`, followed by SHA-256.

Inputs fail closed when they contain:

- duplicate object members;
- `NaN`, positive or negative infinity, or overflow to a non-finite number;
- a lone UTF-16 surrogate;
- an integer or integer-valued number outside `[-9007199254740991, 9007199254740991]`;
- a non-JSON runtime value.

The implementation is pinned through `jcs==0.2.1`. Golden vectors in `canonicalization/runtime-jcs-golden-vectors.json` cover UTF-16 member ordering (including supplementary-versus-BMP order), Unicode, negative zero, decimal and exponent forms, safe integer limits, nested arrays, booleans, null, string escaping, and out-of-domain negatives. `tools/verify_runtime_jcs.py` and the independent ECMAScript implementation `tools/verify_runtime_jcs.mjs` compare exact canonical bytes and SHA-256 values.

## Uniform text checkout projection

Corpus-passport text entries use the separately named domain `UNIFORM_UTF8_TEXT_TO_LF_SHA256_V1`.

This is a checkout projection, not a raw-byte identity claim:

- uniformly LF text is accepted unchanged;
- uniformly CRLF text is projected to LF;
- mixed LF/CRLF, bare CR, UTF-8 BOM, invalid UTF-8, and NUL-bearing binary input are rejected;
- empty UTF-8 text is accepted and hashes as the empty byte string.

The domain name therefore states the proven operation: one uniform UTF-8 text representation is projected to LF before SHA-256. It does not claim that the worktree bytes were originally LF.

## Boundaries

This profile does not define repository checkout policy, release policy, DOI bytes, or a general-purpose checksum domain. It applies only where a runtime-integrity artifact explicitly declares one of the two domain labels above.
