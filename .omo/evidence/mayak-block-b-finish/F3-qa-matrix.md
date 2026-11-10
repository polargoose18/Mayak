F3 independent real-surface QA: APPROVE

Verified commit: ae0e5db437c375872f2972d6e91943278c666004. No product edits or commits. Evidence uses the caller directory because this is not an ulw-loop run.

All requested gates and scenarios passed. The expiry guard intentionally exits 1 for 2026-11-11T00:00:00Z; default make check exits 0. The SIGINT helper process exits 0 after asserting command exit 130; the captured command return is not an OS process exit 130.

Control fixture: byte-identical temporary copy of the existing owner-signed list; no new signature or private key. An isolated user/mount/network namespace maps signed host www.google.com to a local HTTPS server at 93.184.216.34:443. SSL_CERT_FILE supplies temporary CA trust without product hooks. All sockets closed and both temporary directories removed; namespace-local network and hosts changes disappeared on exit.

```json
{
  "manualQa": {
    "surfaceEvidence": [
      {
        "scenarioId": "make check",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "make check",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "make sign-check",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "make sign-check",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "make release-check",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "make release-check",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "go build ./...",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "go build ./...",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "go test -race ./...",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "go test -race ./...",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "gofmt -l .",
        "criterionRef": "F3 gates",
        "surface": "build/test CLI",
        "exactInvocation": "gofmt -l .",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "CI",
        "criterionRef": "IS-6 / todo 10",
        "surface": "PyYAML workflow parser",
        "exactInvocation": "python3 -c 'import yaml,json; w=yaml.safe_load(open('\"'\"'.github/workflows/ci.yml'\"'\"')); assert set(w['\"'\"'jobs'\"'\"'])=={'\"'\"'check'\"'\"','\"'\"'windows'\"'\"','\"'\"'release-check'\"'\"'}; assert w['\"'\"'jobs'\"'\"']['\"'\"'windows'\"'\"']['\"'\"'runs-on'\"'\"']=='\"'\"'windows-2025'\"'\"'; print(json.dumps(w['\"'\"'jobs'\"'\"'],indent=2))'",
        "verdict": "PASS",
        "artifactRefs": [
          "log",
          "cli-harness"
        ]
      },
      {
        "scenarioId": "version",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "surface": "built CLI (fresh XDG_CONFIG_HOME recorded in log)",
        "exactInvocation": "/tmp/mayak-f3-cli-l468med8/mayak version",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "no-control",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "surface": "built CLI (fresh XDG_CONFIG_HOME recorded in log)",
        "exactInvocation": "strace -f -e trace=network -o /home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-no-control.strace /tmp/mayak-f3-cli-l468med8/mayak check",
        "verdict": "PASS",
        "artifactRefs": [
          "log",
          "trace"
        ]
      },
      {
        "scenarioId": "json-no-control",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "surface": "built CLI (fresh XDG_CONFIG_HOME recorded in log)",
        "exactInvocation": "/tmp/mayak-f3-cli-l468med8/mayak check --json",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "limit",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "surface": "built CLI (fresh XDG_CONFIG_HOME recorded in log)",
        "exactInvocation": "/tmp/mayak-f3-cli-l468med8/mayak check --limit 3",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "sigint",
        "criterionRef": "IS-3 / todo 12",
        "surface": "OS subprocess signal to test helper running command handler",
        "exactInvocation": "go test ./cmd/mayak -run TestCheckInterruptSignal -count=1 -v",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "expiry-guard",
        "criterionRef": "IS-4 / todo 11",
        "surface": "opt-in test CLI",
        "exactInvocation": "MAYAK_TARGETS_EXPIRY_GUARD=1 go test -run '^TestEmbeddedListFreshness$' ./targets (expected exit 1; 2026-11-11T00:00:00Z)",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "any-sni",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "openssl s_client -connect 127.0.0.1:19443 -servername arbitrary-f3.example -brief",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "ping",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 http://127.0.0.1:18443/v1/ping",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "reach",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/reach?host=www.google.com'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "fetch-root",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/fetch?host=www.google.com&path=/'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "fetch-robots",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/fetch?host=www.google.com&path=/robots.txt'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "forbidden-ip",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/reach?host=www.google.com&ip=10.22.33.44'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "forbidden-port",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/fetch?host=www.google.com&path=/&port=22'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "bad-path",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/fetch?host=www.google.com&path=/etc/passwd'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "unknown-host",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/reach?host=untrusted-f3.example'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "malformed-query",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 15 'http://127.0.0.1:18443/v1/fetch?host=www.google.com&path=/&ip=%ZZ'",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "tls-no-http",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "socket.create_connection((127.0.0.1,19443)); sendall(b\"GET / HTTP/1.1\\r\\nHost: arbitrary-f3.example\\r\\n\\r\\n\"); recv(4096)",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "rate-limit",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "curl -i --noproxy '*' --max-time 5 http://127.0.0.1:18443/v1/ping",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "privacy",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "control binary HTTP/TLS",
        "exactInvocation": "Inspect complete stdout/stderr after terminate()/communicate(); assert no 127.0.0.1, 10.22.33.44 or arbitrary-f3.example",
        "verdict": "PASS",
        "artifactRefs": [
          "log",
          "node-log"
        ]
      },
      {
        "scenarioId": "port-closed-18443",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "OS TCP cleanup",
        "exactInvocation": "socket.connect_ex to 127.0.0.1:18443 after process teardown (result 111)",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "port-closed-19443",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "OS TCP cleanup",
        "exactInvocation": "socket.connect_ex to 127.0.0.1:19443 after process teardown (result 111)",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "port-closed-443",
        "criterionRef": "IS-5 / todos 4-5",
        "surface": "OS TCP cleanup",
        "exactInvocation": "socket.connect_ex to 93.184.216.34:443 after process teardown (result 111)",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      }
    ],
    "adversarialCases": [
      {
        "scenarioId": "no-control",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "adversarialClass": "missing deployment configuration",
        "expectedBehavior": "Exit 2, exact guard sentence, no stdout, zero network syscalls",
        "verdict": "PASS",
        "artifactRefs": [
          "log",
          "trace"
        ]
      },
      {
        "scenarioId": "json-no-control",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "adversarialClass": "empty machine-readable failure",
        "expectedBehavior": "Exit 2 and stdout empty",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "limit",
        "criterionRef": "IS-1 / IS-2 / todo 2",
        "adversarialClass": "invalid argument boundary",
        "expectedBehavior": "Exit 1 for --limit 3",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "sigint",
        "criterionRef": "IS-3 / todo 12",
        "adversarialClass": "OS interruption",
        "expectedBehavior": "Actual SIGINT; command returns 130, valid measured JSON, unchanged state bytes",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "expiry-guard",
        "criterionRef": "IS-4 / todo 11",
        "adversarialClass": "time boundary",
        "expectedBehavior": "Opt-in guard fails with 2026-11-11; default gate remains green",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "forbidden-ip",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "SSRF query parameter",
        "expectedBehavior": "HTTP 400 without reflecting supplied address",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "forbidden-port",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "SSRF port parameter",
        "expectedBehavior": "HTTP 400",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "bad-path",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "path allowlist bypass",
        "expectedBehavior": "HTTP 400",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "unknown-host",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "host allowlist bypass",
        "expectedBehavior": "HTTP 400",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "malformed-query",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "malformed URL encoding",
        "expectedBehavior": "HTTP 400",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "tls-no-http",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "protocol mismatch",
        "expectedBehavior": "Close plaintext connection without HTTP response",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "rate-limit",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "request flood",
        "expectedBehavior": "HTTP 429 after bucket exhausted",
        "verdict": "PASS",
        "artifactRefs": [
          "log"
        ]
      },
      {
        "scenarioId": "privacy",
        "criterionRef": "IS-5 / todos 4-5",
        "adversarialClass": "sensitive data retention",
        "expectedBehavior": "Client IP, rejected IP, and arbitrary SNI absent from complete node log",
        "verdict": "PASS",
        "artifactRefs": [
          "log",
          "node-log"
        ]
      }
    ],
    "artifactRefs": [
      {
        "id": "log",
        "kind": "command-transcript",
        "description": "Complete invocations, stdout/stderr, exit codes, curl headers/bodies and teardown receipts",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-real-manual-qa.log"
      },
      {
        "id": "trace",
        "kind": "syscall-trace",
        "description": "strace -f -e trace=network for no-control run; exit receipts only, no network syscalls",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-no-control.strace"
      },
      {
        "id": "node-log",
        "kind": "process-log",
        "description": "Complete control-node output; only certificate fingerprint",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-control-node.log"
      },
      {
        "id": "cli-harness",
        "kind": "qa-harness",
        "description": "Exact CLI build, PyYAML assertions, environment isolation and assertions",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-cli-qa.py"
      },
      {
        "id": "ctrl-harness",
        "kind": "qa-harness",
        "description": "Namespace/local upstream setup, real curl/TLS invocations and cleanup",
        "path": "/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish/F3-control-qa.py"
      }
    ]
  }
}
```
