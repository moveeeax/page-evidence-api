# page-evidence-api

A capture service that returns a **court-usable evidence bundle** rather than a screenshot:
PNG, PDF, rendered DOM, response headers, redirect chain, a SHA-256 manifest, and an
RFC 3161 trusted timestamp over that manifest.

Built for affiliate-network and brand-protection compliance teams who have to prove what a
partner's landing page said on the day they approved it — not for developers shopping for
the cheapest screenshot endpoint.

**Status: sealing and verification are implemented. Capture and the HTTP API are not.**
See [what is not here yet](#what-is-not-here-yet) before you judge the scope.

---

## The idea in one diagram

```
artefact bytes ──sha256──▶ manifest.json ──sha256──▶ RFC 3161 token (timestamp.tsr)
```

That is the entire trust chain, and it is deliberately short:

- Change one pixel of the screenshot and its digest stops matching the manifest.
- Change the manifest to cover the new digest and the timestamp stops matching the manifest.
- Forge the timestamp and you need the timestamping authority's private key.

Everything is verifiable **offline**, years later, by someone who does not trust us. That
is the product. `pev verify` is a single static binary with no dependencies outside the Go
standard library and no network access.

## Install

```sh
go install github.com/moveeeax/page-evidence-api/cmd/pev@latest
```

Or from a clone:

```sh
git clone https://github.com/moveeeax/page-evidence-api.git
cd page-evidence-api
go build -o bin/pev ./cmd/pev
```

Go 1.24 or newer. No other dependencies.

## Usage example (this one actually runs)

The repository ships two example bundles: an intact one, and a copy in which a single
phrase in `dom.html` was changed from `up to 20% cashback` to `up to 80% cashback` — the
exact dispute this product exists to settle.

```console
$ ./bin/pev verify testdata/bundles/valid -tsa-roots testdata/tsa-test-root.pem
bundle:   testdata/bundles/valid
id:       peb_971adfcae4957b1b4a6abde1
manifest: sha256:ad24cf087741eb5a473fd5777bb9c566b28c13543c46f193d43cc178ae72b38c

  [PASS] manifest                     schema page-evidence/manifest/v1, 5 artefacts, sealed 2026-07-26T12:00:00Z
  [PASS] capture metadata             http://promo.example.com/summer-cashback -> https://promo.example.net/summer-cashback?aff=1042 (200), 2 redirect(s), HeadlessChrome 126.0.6478.126
  [PASS] artifact capture.json        capture-metadata sha256:375255966f71fab7… (1158 bytes)
  [PASS] artifact dom.html            dom sha256:7363a06ce6e18ef0… (536 bytes)
  [PASS] artifact headers.json        response-headers sha256:3f963e0aa494283e… (184 bytes)
  [PASS] artifact page.pdf            pdf sha256:6b5c22d6e5c6c7be… (611 bytes)
  [PASS] artifact screenshot.png      screenshot sha256:74bd4f0c001aa9c9… (806 bytes)
  [PASS] no unlisted content          every file in the bundle is covered by the manifest
  [PASS] trusted timestamp            manifest sha256 was timestamped at 2026-07-26T12:00:00Z by CN=page-evidence test TSA,O=page-evidence-api tests
  [PASS] timestamp authority          signer chains to a supplied trusted root

RESULT: PASS — every artefact matches the sealed manifest
```

Now the tampered copy:

```console
$ ./bin/pev verify testdata/bundles/tampered -tsa-roots testdata/tsa-test-root.pem
  ...
  [FAIL] artifact dom.html            sha256 is 29600450a99231b2…, manifest says 7363a06ce6e18ef0…
  [PASS] trusted timestamp            manifest sha256 was timestamped at 2026-07-26T12:00:00Z by …

RESULT: FAIL — 1 check(s) failed
$ echo $?
1
```

Note which check fails and which does not: the timestamp is still perfectly valid, because
only an artefact changed. Editing the manifest to cover the altered file breaks the
timestamp instead — there is no consistent forgery without the TSA's key.

Both of the above run in CI on every push.

> The example bundles are timestamped by a **throwaway test authority** whose root is
> committed as `testdata/tsa-test-root.pem`, so the example works offline and forever.
> Real bundles are stamped by a public TSA (FreeTSA, DigiCert as fallback) and you point
> `-tsa-roots` at that authority's root instead. Without `-tsa-roots` the signature is
> still checked, but the report says the chain was not verified rather than pretending
> it was.

### Other commands

```sh
pev inspect testdata/bundles/valid        # what the bundle claims, without verifying it
pev verify  bundle.zip -json              # machine-readable report (directory or .zip)
pev seal    ./capture-dir                 # hash every artefact, write manifest.json
pev stamp   ./capture-dir                 # request an RFC 3161 token over the manifest
```

`pev stamp` is the only command that touches the network, and it refuses to store a token
that does not verify against the request it just sent (matching digest, matching nonce).

## Bundle layout

```
manifest.json      sealed inventory: capture metadata + sha256 of every artefact
timestamp.tsr      RFC 3161 TimeStampResp over sha256(manifest.json)
capture.json       renderer metadata as recorded (also hashed like any artefact)
screenshot.png     the render
page.pdf           the render as PDF
dom.html           the DOM as rendered, after scripts ran
headers.json       final response headers
```

`manifest.json` and `timestamp.tsr` are reserved names; **every other file in the bundle
must be listed in the manifest**, or verification fails. A bundle cannot smuggle in
uncovered content.

The timestamp covers the bytes of `manifest.json` exactly as stored. The verifier never
re-serialises the manifest, so reformatting it can never silently invalidate — or silently
revalidate — a bundle.

Full field reference: [docs/bundle-format.md](docs/bundle-format.md).

## What `verify` actually checks

| Check | What it proves |
| --- | --- |
| manifest schema and shape | the bundle is a v1 bundle and its metadata is complete |
| per-artefact size + SHA-256 | no artefact was altered, truncated or swapped |
| no unlisted content | nothing was added to the bundle after sealing |
| TSTInfo message imprint | the timestamp is over *this* manifest, not another one |
| CMS signed attributes | the signature covers the TSTInfo in this token |
| CMS signature | the token was signed by the holder of the TSA key |
| ESS signingCertificate | the token names the certificate that signed it |
| timestamping EKU, marked critical | the signer is a timestamping authority, per RFC 3161 §2.3 |
| certificate validity at genTime | the TSA certificate was live when it signed |
| chain to `-tsa-roots` | *who* the authority is (skipped, and reported as skipped, without roots) |

Nonce checking is implemented too, but only the process that issued the request holds the
nonce, so `pev stamp` uses it and `pev verify` cannot.

## Repository layout

```
cmd/pev              the CLI: seal, stamp, verify, inspect
cmd/genfixture       dev tool that regenerates testdata/
internal/evidence    manifest + capture data model, sealing, hashing
internal/bundle      directory or zip bundle as an fs.FS, reproducible packing
internal/rfc3161     RFC 3161 + CMS: request building, token parsing, offline verification
internal/verify      bundle verification and the report
internal/tsatest     throwaway TSA used by tests and fixtures
testdata/            example bundles, one intact and one tampered
```

`internal/rfc3161` is stdlib-only ASN.1 and CMS on purpose. A verifier a compliance team
can rebuild from source with `go build`, with no module downloads, is easier to trust than
one that pulls a dependency tree.

## Development

```sh
make check      # gofmt, go vet, go test -race
make demo       # verify both example bundles
make fixtures   # regenerate testdata/ (only when the format changes)
```

## What is not here yet

Deliberately, in order:

1. **Capture worker** — headless Chrome with wait rules, full-page stitching, PDF export,
   resource blocking, per-capture timeout and memory caps. Needs a Chrome runtime.
2. **HTTP API** — `POST /v1/capture`, API keys, per-key rate limits and monthly quotas,
   usage endpoint. Needs a datastore.
3. **Storage** — S3-compatible object storage, per-plan retention, signed download URLs,
   zip export of a date range. Needs an object-storage account.
4. **Commerce** — Paddle checkout, plan-to-quota mapping. Needs a Paddle account.
5. **Docs site** — live capture demo and a public page where anyone can drop a bundle and
   check it.

Explicitly **out of v1** and not planned: scheduled monitoring and change detection,
WARC/WACZ, video, HAR, captures behind login/2FA/CAPTCHA, HTML-string-to-PDF templating,
human attestation or notarisation, SOC 2, on-prem deployment, SLAs, team seats, OG-image
templating, multi-region rendering.

## Licence

Not yet decided. Until a licence file is added, all rights are reserved.
