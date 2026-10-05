# Repository Guidelines

## Project Structure & Module Organization

`cmd/st-core/main.go` is the CLI entry point. Core packages live under `internal/`, grouped by responsibility: configuration, routing, DNS, gateway, proxy server, certificates, load balancing, and speed testing. `mobilecore/` exposes the HTTP and SOCKS5 proxy through Go Mobile. Keep package tests beside their code as `*_test.go`. `config.yaml` is the example runtime configuration, `iplist/` holds bundled provider ranges, and `scripts/build-mobile.sh` creates mobile artifacts in the ignored `dist/` directory.

## Build, Test, and Development Commands

Use the Go version in `go.mod` (currently 1.26.3).

- `go build -o st-core ./cmd/st-core` builds the CLI.
- `go run ./cmd/st-core check` validates `config.yaml` without starting listeners.
- `go run ./cmd/st-core start proxy` runs the configured local proxy listeners; stop it with Ctrl-C.
- `go test ./...` runs all package tests; `go vet ./...` checks common Go mistakes.
- `./scripts/build-mobile.sh android` or `./scripts/build-mobile.sh ios org.example.app` builds the mobile binding. Android needs the SDK and NDK; iOS needs macOS and Xcode.

Pass `-config /path/to/config.yaml` before a CLI command to use another configuration file.

## Coding Style & Naming Conventions

Format Go files with `gofmt`; use its tab-based indentation and standard import grouping. Keep package names short and lowercase, exported identifiers in `MixedCaps`, and tests named `TestBehavior` in `*_test.go`. Prefer focused changes in the responsible `internal/` package over adding logic to the CLI entry point. No separate formatter or linter configuration is present.

## Testing Guidelines

Use Go's `testing` package and run `go test ./...` before submitting changes. Add focused tests for configuration validation, routing, origin selection, and proxy behavior when modifying those paths. Use table-driven subtests where inputs vary. There is no stated coverage threshold; test observable behavior and failure cases rather than targeting a percentage.

## Commit & Pull Request Guidelines

Recent commits use concise imperative subjects with a `feat:` prefix for features (for example, `feat: add startup IP selection and DNS-backed origins`). Follow that pattern with an appropriate type such as `fix:` or `docs:`. In pull requests, describe the behavior changed, note any configuration or platform impact, and include the commands you ran. Link a related issue when one exists; attach screenshots only for visible app changes.

## Security & Configuration

Do not commit generated CA keys, certificates, `.env` files, or local YAML overrides; these are ignored. Preserve TLS verification defaults. If a change requires `origin.insecure_skip_verify`, explain the risk explicitly in its review.
