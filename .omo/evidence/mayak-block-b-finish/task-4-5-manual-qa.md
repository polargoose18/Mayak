# manualQa

```json
{
  "manualQa": {
    "surfaceEvidence": [
      {
        "scenarioId": "ping",
        "criterionReference": "SPEC 21.1: ping 200 empty body",
        "surface": "HTTP binary",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 http://127.0.0.1:18443/v1/ping",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "reach",
        "criterionReference": "SPEC 21.1: exact reachable response",
        "surface": "HTTP binary",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=www.youtube.com'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "fetch-root",
        "criterionReference": "SPEC 21.1: exact fetch response; path /",
        "surface": "HTTP binary",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=www.youtube.com&path=/'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "fetch-robots",
        "criterionReference": "SPEC 21.1: exact fetch response; path /robots.txt",
        "surface": "HTTP binary",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=www.youtube.com&path=/robots.txt'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "any-sni",
        "criterionReference": "SPEC 21.1: any-SNI TLS handshake then close",
        "surface": "TLS binary",
        "exactInvocation": "openssl s_client -connect 127.0.0.1:18444 -servername target.example < /dev/null",
        "verdict": "PASS",
        "artifactRefs": [
          "tls"
        ]
      },
      {
        "scenarioId": "tls-disabled",
        "criterionReference": "SPEC 21.1: empty TLS address disables listener",
        "surface": "binary startup",
        "exactInvocation": "./mayak-ctrl --addr 127.0.0.1:18443 --tls-addr '' --targets targets/targets.signed.json",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      }
    ],
    "adversarialCases": [
      {
        "scenarioId": "bad-ip",
        "criterionReference": "SPEC 21.1: request restrictions",
        "adversarialClass": "unknown query key / SSRF",
        "expectedBehavior": "400 with fixed message",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=example.org&ip=10.0.0.1'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "bad-port",
        "criterionReference": "SPEC 21.1: request restrictions",
        "adversarialClass": "unknown query key / SSRF",
        "expectedBehavior": "400 with fixed message",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=example.org&path=/&port=443'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "bad-path",
        "criterionReference": "SPEC 21.1: request restrictions",
        "adversarialClass": "path authorization",
        "expectedBehavior": "400: path must be / or /robots.txt",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=example.org&path=/admin'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "unknown-host",
        "criterionReference": "SPEC 21.1: request restrictions",
        "adversarialClass": "signed host authorization",
        "expectedBehavior": "400: host is not in the targets list",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=not-in-list.invalid'",
        "verdict": "PASS",
        "artifactRefs": [
          "http"
        ]
      },
      {
        "scenarioId": "client-ip-privacy",
        "criterionReference": "SPEC 21.1: no client IP in server logs",
        "adversarialClass": "privacy",
        "expectedBehavior": "127.0.0.1 and submitted 10.0.0.1 absent from the actual server output; command transcripts intentionally contain test addresses.",
        "exactInvocation": "Python membership scan of control-server.log, control-server-disabled.log and control-server-final.log",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "tls",
          "review"
        ]
      },
      {
        "scenarioId": "malformed-reach-ip",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "malformed forbidden query value",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=www.youtube.com&ip=%ZZ'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "malformed-reach-port",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "malformed forbidden query value",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=www.youtube.com&port=%ZZ'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "malformed-fetch-ip",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "malformed forbidden query value",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=www.youtube.com&path=/&ip=%ZZ'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "malformed-fetch-port",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "malformed forbidden query value",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=www.youtube.com&path=/&port=%ZZ'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "duplicate-host",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "duplicate singleton field",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/reach?host=www.youtube.com&host=evil.invalid'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "duplicate-path",
        "criterionReference": "SPEC 21.1; verifier request 1",
        "surface": "HTTP compiled binary",
        "adversarialClass": "duplicate singleton field",
        "expectedBehavior": "HTTP 400 before DNS or endpoint work; response does not echo query values.",
        "exactInvocation": "curl -i --silent --show-error --max-time 12 'http://127.0.0.1:18443/v1/fetch?host=www.youtube.com&path=/&path=/robots.txt'",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks"
        ]
      },
      {
        "scenarioId": "rate-capacity",
        "criterionReference": "Verifier request 2: bounded limiter never bypasses rate enforcement",
        "surface": "HTTP compiled binary plus deterministic request-boundary regression",
        "adversarialClass": "resource saturation",
        "expectedBehavior": "Fill 10,000 live client buckets; a fresh client is refused with HTTP 429. All 21 requests were refused, and deterministic test proves tracked clients retain remaining allowance.",
        "exactInvocation": "curl -i --config .omo/evidence/mayak-block-b-finish/control-saturation.curl; repeat 21 times: curl -i --silent --show-error --max-time 3 --interface 127.2.0.1 http://127.0.0.1:18443/v1/ping",
        "verdict": "PASS",
        "artifactRefs": [
          "http",
          "checks",
          "saturation-config"
        ]
      },
      {
        "scenarioId": "signed-list-freshness",
        "criterionReference": "Verifier request 3: list loader uses Verify with current time",
        "surface": "Executed Go regression; clock-controlled production loader / HTTP handler with real TLS upstream as applicable",
        "adversarialClass": "expired or excessively future-dated signed list",
        "expectedBehavior": "Load the same trusted signed fixture at supplied clock times: fresh accepted; expired and future-invalid refused.",
        "exactInvocation": "go test ./cmd/mayak-ctrl -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "checks"
        ]
      },
      {
        "scenarioId": "bogon-refusal",
        "criterionReference": "Verifier request 4: resolution and dial bogon rejection",
        "surface": "Executed Go regression; clock-controlled production loader / HTTP handler with real TLS upstream as applicable",
        "adversarialClass": "private and mixed DNS answers",
        "expectedBehavior": "Both endpoints refuse loopback, private, IPv6, mapped IPv4 and mixed public/private answers before dial; dial hook separately rejects bogons and accepts a public address.",
        "exactInvocation": "go test ./cmd/mayak-ctrl -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "checks"
        ]
      },
      {
        "scenarioId": "oversized-body",
        "criterionReference": "Verifier request 4: capped response body and hash",
        "surface": "Executed Go regression; clock-controlled production loader / HTTP handler with real TLS upstream as applicable",
        "adversarialClass": "oversized HTTPS body",
        "expectedBehavior": "Real TLS upstream sends more than probe.MaxBody; returned size is exactly the cap, body_hash equals SHA-256 of retained prefix, upstream status is preserved, and response has exactly the three specified keys.",
        "exactInvocation": "go test ./cmd/mayak-ctrl -count=2 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "checks"
        ]
      }
    ],
    "artifactRefs": [
      {
        "id": "http",
        "kind": "HTTP transcript",
        "description": "Exact binary startup and curl -i commands and responses, server logs and process cleanup. Initial unlisted-host requests are authorization cases only; www.youtube.com supplies the success cases.",
        "path": ".omo/evidence/mayak-block-b-finish/task-4-control-api.log"
      },
      {
        "id": "tls",
        "kind": "TLS transcript",
        "description": "Exact openssl s_client invocation, certificate, completed handshake and closed connection, server log privacy search and cleanup.",
        "path": ".omo/evidence/mayak-block-b-finish/task-5-any-sni.log"
      },
      {
        "id": "checks",
        "kind": "scoped checks log",
        "description": "gofmt, build, vet, and package tests with count=1 and count=2, all exited zero.",
        "path": ".omo/evidence/mayak-block-b-finish/control-checks.log"
      },
      {
        "id": "review",
        "kind": "artifact validation log",
        "description": "Parsed response shapes, TLS transcript review, server privacy log scan, source hashes and final port cleanup checks.",
        "path": ".omo/evidence/mayak-block-b-finish/control-evidence-review.log"
      },
      {
        "id": "saturation-config",
        "kind": "curl configuration",
        "description": "Exact 9,999 requests with distinct loopback source interfaces; first ordinary client already occupies the remaining bucket.",
        "path": ".omo/evidence/mayak-block-b-finish/control-saturation.curl"
      },
      {
        "id": "regression-before",
        "kind": "failing baseline test log",
        "description": "Regression run before fixes: malformed queries reach DNS, saturated map admits fresh client, expired/future list accepted; bogon and oversized-body tests already pass.",
        "path": ".omo/evidence/mayak-block-b-finish/control-regression-before.log"
      },
      {
        "id": "server-post-fix",
        "kind": "raw binary server output",
        "description": "Actual stdout/stderr from the post-fix binary; fingerprint only, with no client IP or SNI.",
        "path": ".omo/evidence/mayak-block-b-finish/control-server-post-fix.log"
      }
    ]
  },
  "coverageLimits": [
    "Freshness is exercised through the exact production list loader with explicit clock values; binary startup uses time.Now(). A valid trusted signed repository fixture is used without accessing a signing private key.",
    "Bogon and oversized-body scenarios are executed regressions, not binary DNS or clock manipulation; their surfaces and exact invocation are listed separately.",
    "Supplied TLS certificate files, default privileged-port binding, persistent list revision rollback, file-size refactoring and unrelated review findings were outside this four-item fix request.",
    "gopls is not installed; go vet, compiler and scoped tests passed."
  ]
}
```
