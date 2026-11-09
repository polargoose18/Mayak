.PHONY: test vet fmt check sign-check release-check targets-expiry

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

check: fmt vet test

# Checks that targets/targets.signed.json, if present, is signed by one of the
# keys in internal/targets/pubkeys.go.
sign-check:
	go test -count=1 -v -run '^TestSignedTargetsFile$$' ./internal/targets

# Fails while internal/targets/pubkeys.go still holds the test key (the line
# with the TESTKEY label). Run before tagging a release; CI runs it on v* tags.
release-check:
	@if grep -n '", *// TESTKEY' internal/targets/pubkeys.go; then \
		echo "release-check: pubkeys.go still has the TESTKEY; replace it with the real key (docs/KEYS.md)"; \
		exit 1; \
	fi
	@echo "release-check: no test key in pubkeys.go"

# Warns when the built-in targets list is about to expire (within 7 days) or
# has expired. Intentionally NOT part of `check`: an expiring list must not
# block unrelated PRs. Re-sign the list (docs/KEYS.md, "Перед релизом").
targets-expiry:
	MAYAK_TARGETS_EXPIRY_GUARD=1 go test -count=1 -run '^TestEmbeddedListFreshness$$' ./targets
