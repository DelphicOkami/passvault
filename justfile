# Run the in-tree dummy adapter against the live UI assets.
# Useful for exercising a frontend change end-to-end without standing
# up Passman or Passbox.
run-test:
    cd examples/runnable && go run -tags desktop,production .

test:
    go test ./...

vet:
    go vet ./...
