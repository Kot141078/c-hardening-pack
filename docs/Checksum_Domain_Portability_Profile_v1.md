# Checksum Domain Portability Profile v1

## Scope and boundary

This profile verifies the two existing standalone v0.1 checksum manifests across Git and operating-system checkout representations. It does not change either manifest, any manifest entry, any checksum-manifested canonical file, a DOI artifact, or a release tag. It is an integrity test profile and validator rule, not a runtime-integrity ontology or release authorization.

The protected Git baseline is `9a33e3866cde19939be22a903967bc94f566db76`. Exact Git-blob validation compares the candidate's two manifest blobs and all 37 distinct protected entry blobs byte-for-byte with that baseline. This comparison is separate from checksum-domain projection.

## Declared domains

Every path in each manifest appears exactly once in one of three explicit domains in `CHECKSUM_DOMAIN.json`:

- `lf_text_bytes`: canonical UTF-8 text with LF line endings;
- `crlf_text_bytes`: canonical UTF-8 text with CRLF line endings;
- `raw_bytes`: bytes are hashed without decoding or transformation.

The current partition contains 24 LF-text paths, 3 CRLF-text paths, and 10 raw PDF paths per manifest. The two manifests must contain the same 37 path/digest pairs and the same domain partition, yielding exactly 74 checks. A missing, extra, duplicate, case-alias, or conflicting declaration fails closed.

Declared text uses strict UTF-8. UTF-8, UTF-16, and UTF-32 byte-order marks are forbidden; NUL and invalid UTF-8 are rejected; Unicode normalization is not performed. A newline-free text file, including an empty file, is accepted because it has no conflicting newline representation. Uniform LF and uniform CRLF worktree forms are accepted. Mixed CRLF plus LF and bare CR are rejected before transformation.

## Three distinct evidence claims

### Git blob

`--source git-blob --git-ref <commit>` resolves one exact commit and accepts only regular tracked blobs. It first compares raw candidate blob bytes to the pinned baseline. It then separately projects declared text into the release canonical domain for manifest-digest verification. The output reports raw digest matches, transformed domain matches, and protected baseline blob matches separately. A transformed checksum-domain match is never described as raw Git-blob equality.

The three CRLF-domain files are stored as LF Git blobs at the protected baseline, so their canonical-domain projection is expected to transform LF to CRLF. Across both manifests, this produces 68 raw digest matches and 6 transformed-domain matches while the 39 distinct protected blobs (37 files plus 2 manifests) remain exact baseline matches.

### Worktree

`--source worktree` reads the current checkout. A declared text file may be uniformly LF or uniformly CRLF because `core.autocrlf` can alter only its checkout representation. The validator decodes it as strict UTF-8, rejects ambiguous or mixed forms, transforms it to the declared canonical domain, and hashes that result. Raw paths are never transformed. Every file and ancestor must remain a regular in-root path; symlink and Windows reparse traversal are rejected.

### Extracted release archive

`--source release-archive --git-ref <commit> --archive-root <path>` uses the policy blob from that exact resolved commit and reads evidence from the named extracted archive root. The archive need not contain the policy file, but it must contain both checksum manifests and every declared entry. The mode performs no checkout normalization. Declared text must already use its canonical LF or CRLF representation, and raw files must match exactly. This mode verifies supplied extracted archive bytes only; it does not assert that an archive was released, published, or DOI-bound.

## Engineering rationale

On Windows with `core.autocrlf=true`, a clean checkout expands the 24 LF canonical text blobs to CRLF. Hashing the worktree bytes directly therefore produces false mismatches even though the committed content is unchanged. Conversely, silently replacing every CR or LF can conceal a mixed file assembled from different producers. The validator first classifies the complete newline stream, rejects mixed or bare-CR input, and only then performs one declared transformation. Binary PDFs stay in `raw_bytes`, so no text heuristic can rewrite them.

## Manifest and path parsing

Checksum lines use exactly 64 hexadecimal characters, two ASCII spaces, and one canonical repository-relative POSIX path. Absolute paths, drive-qualified paths, backslashes, dot segments, empty segments, control characters, encoded structural traversal, NTFS alternate-data-stream syntax, Windows device names, Windows-forbidden filename characters, trailing dots/spaces, malformed lines, duplicate logical paths, and case aliases are rejected. The manifest itself must be strict UTF-8 without BOM or mixed/bare-CR line endings. Each manifest's normalized LF bytes are bound by `canonical_manifest_sha256`.

## CI and local commands

Pull-request CI checks out `${{ github.event.pull_request.head.sha }}` rather than a synthetic merge ref, prints and asserts the resolved `HEAD`, and runs on `ubuntu-latest` and `windows-latest`. It verifies exact Git blobs, the direct worktree, unit tests, and a second clean clone using `core.autocrlf=false` on Linux or `core.autocrlf=true` on Windows.

```text
python tools/verify_checksum_domain.py --source worktree
python tools/verify_checksum_domain.py --source git-blob --git-ref HEAD
python tools/verify_checksum_domain.py --source release-archive --git-ref HEAD --archive-root PATH_TO_EXTRACTED_ARCHIVE
python -m unittest discover -s tests -p "test_checksum_domain.py" -v
```

No repository-wide `.gitattributes` rule is required or introduced.
