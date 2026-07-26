# Evidence bundle format v1

Schema identifier: `page-evidence/manifest/v1`.

A bundle is a directory, or a zip archive of that directory. Both verify identically; a
zip whose entries all sit under one wrapping folder is rooted at that folder automatically.

## Files

| File | Reserved | Description |
| --- | --- | --- |
| `manifest.json` | yes | Sealed inventory. Cannot hash itself, so it is not listed as an artefact. |
| `timestamp.tsr` | yes | DER `TimeStampResp` (RFC 3161) over `sha256(manifest.json)`. Written after the manifest, so it is not listed either. |
| everything else | no | Must be listed in `manifest.json`. Unlisted files fail verification. |

Conventional artefact names produced by the capture worker: `screenshot.png`, `page.pdf`,
`dom.html`, `headers.json`, `capture.json`.

## manifest.json

```json
{
  "schema": "page-evidence/manifest/v1",
  "bundle_id": "peb_971adfcae4957b1b4a6abde1",
  "sealed_at": "2026-07-26T12:00:00Z",
  "hash_algorithm": "sha256",
  "capture": { "...": "see below" },
  "artifacts": [
    {
      "path": "dom.html",
      "role": "dom",
      "media_type": "text/html; charset=utf-8",
      "size": 536,
      "sha256": "7363a06ce6e18ef00e46e310c885aec17d93113d220bf780fc424217ca577a3d"
    }
  ]
}
```

| Field | Notes |
| --- | --- |
| `schema` | Must match exactly. A verifier that does not know the schema must refuse, not guess. |
| `bundle_id` | `peb_` + 24 hex characters, derived from the final URL, the capture start time and the artefact digests. Sealing the same capture twice yields the same id. |
| `sealed_at` | UTC, second precision. |
| `hash_algorithm` | `sha256` in v1. Any other value is refused. |
| `artifacts[]` | Sorted by `path`. Paths are slash-separated and relative to the bundle root. |
| `artifacts[].role` | `screenshot`, `pdf`, `dom`, `response-headers`, `redirect-chain`, `capture-metadata`, `other`. |

Artefact digests are lowercase hex SHA-256 of the file bytes. `size` is redundant with the
digest and checked anyway: a size mismatch gives a clearer failure than a hash mismatch.

Unknown fields are rejected on parse. A manifest carrying meaning this verifier does not
understand must not be reported as fully checked.

## capture

Embedded in the manifest, so the provenance metadata is covered by the timestamp and not
merely shipped alongside it. The renderer also writes it to `capture.json`, which is hashed
like any other artefact.

```json
{
  "requested_url": "http://promo.example.com/summer-cashback",
  "final_url": "https://promo.example.net/summer-cashback?aff=1042",
  "redirect_chain": [
    { "url": "http://promo.example.com/summer-cashback", "status": 301,
      "location": "https://promo.example.com/summer-cashback" }
  ],
  "http_status": 200,
  "remote_ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 … HeadlessChrome/126.0.0.0 …",
  "viewport": { "width": 1280, "height": 800, "device_scale": 2 },
  "full_page": true,
  "response_headers": { "Content-Type": ["text/html; charset=utf-8"] },
  "started_at": "2026-07-26T11:59:58Z",
  "finished_at": "2026-07-26T12:00:00Z",
  "renderer": { "name": "HeadlessChrome", "version": "126.0.6478.126" }
}
```

Validation rules enforced at seal time and again at verify time:

- `requested_url` and `final_url` must be absolute `http`/`https` URLs with a host.
- `http_status` must be 100–599; every `redirect_chain[].status` must be 3xx.
- `user_agent`, `renderer.name` and `renderer.version` must be non-empty.
- `viewport` dimensions and `device_scale` must be positive.
- `started_at` and `finished_at` must be set, and `finished_at` must not precede
  `started_at`.

A bundle with empty provenance is worse than no bundle: it looks sealed while saying
nothing about what was fetched.

## timestamp.tsr

The raw DER `TimeStampResp` as returned by the TSA, stored unmodified — including the
`PKIStatusInfo` wrapper — so the response can be re-examined exactly as it arrived.

The message imprint is `SHA-256` over the **bytes of `manifest.json` as stored in the
bundle**, including its trailing newline. The verifier never re-serialises the manifest to
compute this digest.

Tokens are requested with `certReq` set, so the TSA certificate chain is embedded in the
token itself and the bundle needs nothing external to be verified.

Verification steps, in order, all offline:

1. `PKIStatus` is `granted` or `grantedWithMods` and a token is present.
2. The CMS content type is `id-signedData` and the encapsulated content is `id-ct-TSTInfo`.
3. Signed attributes contain `contentType` = `id-ct-TSTInfo` and a `messageDigest` equal to
   the digest of the encapsulated `TSTInfo`.
4. The signature over the DER `SET OF` signed attributes verifies under the signer
   certificate's public key.
5. The ESS `signingCertificateV2` (or v1) attribute names that same certificate.
6. The signer certificate carries the timestamping EKU and only that, marked critical.
7. The `TSTInfo` message imprint equals `sha256(manifest.json)`.
8. `genTime` falls inside the signer certificate's validity window.
9. If TSA roots are supplied, the signer chains to one of them with the timestamping EKU,
   evaluated at `genTime`.

Step 9 is the only one that identifies *who* signed. Without roots, the report states that
the chain was not checked; it never claims a verification it did not perform.

`genTime` is parsed from `GeneralizedTime` with or without fractional seconds, since public
TSAs differ on this.

## Versioning

Any change to the meaning of an existing field, or any new field a verifier must understand
to judge a bundle correctly, means a new schema identifier. Old bundles must keep verifying
with the verifier that shipped for their schema.
