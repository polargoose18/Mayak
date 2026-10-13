.PHONY: test vet fmt check sign-check

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
