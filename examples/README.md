# Proposal examples

These four files demonstrate PIC proposal structure. They are not verified
approvals or ready-to-execute authorizations:

| File | Scenario |
| --- | --- |
| `api_key_rotation.json` | Rotate a production payment API key and revoke the old key. |
| `multi_step_workflow.json` | Archive a resolved incident, then notify its owner. |
| `pii_export.json` | Export personal data for a stated business purpose. |
| `resource_deletion.json` | Delete an expired project workspace and its resources. |

Each example declares trusted provenance but includes no authority-bearing
signature evidence. With the default `strict_trust=True` verification pipeline,
self-asserted trust is treated as untrusted, so these high-impact proposals are
blocked. This is intentional: the examples show the proposal shape, not how to
bypass the secure default.

An intended allow path requires authority-bearing signature evidence linked to
the relevant provenance, evidence verification enabled, and a configured
keyring containing the trusted signer's public key. A `trusted` label by itself
does not authorize an action.
