.PHONY: test vet fmt check sign-check release-check

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
