# PIC v0.8.3 HERMETICUM stress test - provenance note

PIC v0.8.3 underwent an independent public-material-only protocol stress test.
This is not certification, endorsement, an audit, or a general security
guarantee.

This page is a PIC-authored provenance note. It records where PIC-maintained
conformance vectors originate and where documented-only cases are represented
without a vector. It does not reproduce reviewer-authored sealed reports,
PDFs, ZIPs, methodology documents, working artifacts, or post-pilot records.
Those materials remain under the reviewer's canonical control unless
separately published by the reviewer.

## Attribution

```
HERMETICUM B.C.E. S.r.l.
Independent Protocol Stress Test methodology
Manuel Coletta, Founder
```

## Scope

- Subject: PIC v0.8.3, `pic-standard/pic-standard` at commit `1778010f`.
- Character: independent, public-material-only, single-engagement.
- Adaptation: PIC has adapted selected review findings into PIC-maintained
  conformance vectors under Apache-2.0. Adapted vectors carry origin
  attribution in their `source` field. The reviewer's original material is
  not redistributed here.

## Contribution boundary

- **Not redistributed**: HERMETICUM PREEXEC/POSTEXEC sealed packages, PDFs,
  ZIPs, methodology documents, post-pilot records, working artifacts,
  trademarks, and branding.
- **Redistributed from HERMETICUM**: nothing. PIC's vectors are PIC-authored
  adaptations under Apache-2.0, not copies of HERMETICUM material.
- **Attribution**: each adapted vector's `source` field names the origin case
  (Phase 1 finding or ADV-N).
- **Canonical case study**: forthcoming. This page will be updated to link to
  the reviewer's canonical public case study when it is published.

## Adapted-vector provenance

Each row maps a review-origin case to the PIC-maintained conformance vector
that carries its regression protection in v0.9.0a2. Documented-only cases are
listed with the reason they are not expressed as a single-proposal manifest
vector.

| origin case | PIC-maintained vector | outcome type |
|---|---|---|
| Phase 1 - SHA-256 hex-casing ambiguity | `core-block-003-uppercase-sha256-schema-reject` | adapted vector |
| Phase 2 - ADV-001 cross-proposal trust non-persistence | (none) | documented-only |
| Phase 2 - ADV-002 orphaned trusted evidence | `evidence-block-034-orphaned-evidence-no-trust-upgrade` | adapted vector |
| Phase 2 - ADV-003 duplicate provenance ID | `core-block-004-duplicate-provenance-id` | adapted vector |
| Phase 2 - ADV-004 low-impact + invalid evidence | (none) | documented-only |
| Phase 2 - ADV-005 raw-byte BOM/CRLF | `evidence-allow-010-hash-raw-bytes-bom-crlf` | adapted vector |
| Phase 2 - ADV-006 ambient vs embedded keyring | (none) | documented-only |
| Phase 2 - ADV-007 NFC/NFD non-normalization | `canon-011-nfd-no-normalization` | adapted vector |

## Documented-only cases

- **ADV-001 (cross-proposal trust non-persistence).** The regression check is
  that a `verify_proposal()` call does not inherit trust state from an earlier
  call. The current conformance manifest evaluates one proposal per vector
  entry; a two-proposal sequence with a state assertion between the calls is
  not expressible in the current runner. Preserved as a Python-level property
  of `pipeline.verify_proposal`, which holds no cross-call state.
- **ADV-004 (low-impact + invalid evidence).** Under v0.9.0a2 pipeline
  semantics, `options.verify_evidence=true` combined with failing evidence
  returns `PIC_EVIDENCE_FAILED` regardless of impact. The alternative shape
  (low-impact + `verify_evidence=false` + malformed evidence in the proposal
  body) is trivially an `allow` because the pipeline never enters the evidence
  step; it does not meaningfully exercise evidence handling. Neither shape is
  a strong enough conformance vector; the property is documented here only.
- **ADV-006 (ambient vs embedded keyring isolation).** The regression check is
  that PIC ignores a hostile ambient keyring when the proposal (or its
  invocation context) declares an embedded keyring. This is an
  environment-isolation property, not a proposal-level property; the
  conformance runner controls keyrings per vector via `embedded_keyring`, not
  via ambient process state, so a hostile-ambient scenario cannot be
  represented as a single-vector JSON. Preserved as an operator-level
  deployment property.

## Change record after v0.8.3

The v0.9.0a2 hardening work includes SHA-256 wire representation tightening,
the `PIC_DUPLICATE_ID` error code, exact tool-binding, strict Base64 signature
representation, and the adapted conformance vectors listed above. The v0.8.3
review record itself is not retroactively edited; the adapted vectors and the
runtime hardening apply forward on `main`.
