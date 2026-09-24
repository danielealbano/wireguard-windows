# Go Rules — ABSOLUTE RULES

These rules apply to ANY Go code in ANY project where this file is present. They are **VERY STRICT and ABSOLUTELY NON-NEGOTIABLE**!
They are AGNOSTIC: project-specific details (where the Go code lives, its build environment, its command targets, and any documented exceptions) live in the project-specific rule file (`project.md`) and the canonical docs it references. When a rule below allows a "documented exception", that exception MUST be documented in `project.md` — otherwise it does not exist.

## 1) Architecture & Idioms — ABSOLUTE RULES

### Go idioms first
- You MUST follow Effective Go, the Go Code Review Comments wiki, and the Go Proverbs.
- You MUST ALWAYS prefer simplicity over cleverness. Clear is better than clever.
- You MUST accept interfaces, return structs.
- You MUST keep packages, functions, and files small and cohesive; you MUST NEVER create "util" or "common" mega-packages.
- You MUST use composition (embedding) rather than deep type hierarchies.
- You MUST export only what consumers need; keep the public API surface minimal.
- You MUST NEVER create APIs that accept nils — it usually means too many things are being done in one place and a refactor / split is required.
- You MUST keep the responsibilities in the code narrow.
- You MUST ALWAYS write code that is testability friendly.
- **Fixed foreign ABIs are a hard contract.** When Go code exposes an ABI to another language (cgo `//export` functions consumed through a C header), the exported names and signatures MUST stay in sync with EVERY consumer declared in `project.md`. Change one → change all. Do NOT bolt constructor-DI / functional-options / `context.Context`-first patterns onto a fixed exported ABI whose entry points are defined by the foreign caller; apply those patterns to the Go code BEHIND the ABI.

### Interface-first and testability
- You MUST define interfaces at the **consumer** site, not the provider, following Go convention.
- You MUST default to interfaces for components that touch external systems or contain business logic that should be unit tested in isolation.
- You MUST keep interfaces small (1–3 methods). You MUST ALWAYS prefer composing small interfaces over large ones.
- You MUST ALWAYS wrap third-party clients (HTTP, feed, messaging, storage) behind your own interface so you can swap or mock them.

### Constructors and configuration
- You MUST use the functional options pattern for configurable constructors: `func(*T) error` option functions.
- Constructor functions MUST be named `NewXxx(requiredArgs, ...options)`.
- Constructor dependencies MUST be interfaces (or plain values) wherever a boundary exists — accept abstractions, return concretions.

### Dependency injection
- You MUST pass dependencies explicitly via constructor parameters or functional options.
- You MUST NEVER rely on package-level globals or `init()` for wiring dependencies.
- `context.Context` MUST be the first parameter of any function that does I/O or may be cancelled.

### Concurrency and goroutines
You MUST ALWAYS assume the system can run in parallel: multiple requests, multiple goroutines, retries, overlapping operations.

You MUST:
- design for idempotency where appropriate (retries, replays, and duplicate events MUST be safe),
- protect shared mutable state with `sync.Mutex`, `sync.RWMutex`, channels, or `sync/atomic`,
- use `context.Context` for cancellation and timeouts,
- handle retries safely without duplicate side effects,
- give every goroutine a clear shutdown path (via `context.Context` cancellation, channel close, or `sync.WaitGroup`),
- use `errgroup.Group` (from `golang.org/x/sync/errgroup`) for managing groups of goroutines with error propagation,
- NEVER fire-and-forget goroutines in production code,
- NEVER launch goroutines that can leak (you MUST ALWAYS ensure they can be stopped via context or channel close).

## 2) Coding Standards — ABSOLUTE RULES

### Validation
- You MUST ALWAYS validate inputs at the boundary.
- You MUST use struct tags or explicit validation functions.
- You MUST return structured error responses with enough detail for the caller to fix the issue.

### Error handling
- You MUST ALWAYS check and handle errors. You MUST NEVER use `_` to discard errors unless there is a documented justification.
- You MUST wrap errors with context using `fmt.Errorf("operation description: %w", err)`.
- You MUST use sentinel errors (`var ErrNotFound = errors.New(...)`) for errors that callers need to match with `errors.Is`.
- You MUST use custom error types (implementing the `error` interface) when callers need to inspect error details with `errors.As`.
- You MUST NEVER panic in library code. Panics are acceptable only for truly unrecoverable programmer errors in `main` or `init`.
- You MUST return errors, not log-and-continue, unless the error is truly informational.

### Context usage
- `context.Context` MUST be the first parameter of any function that performs I/O, calls external services, or may need cancellation.
- You MUST ALWAYS propagate context through the call chain; you MUST NEVER create a new background context in the middle of a request.
- You MUST use `context.WithTimeout` or `context.WithDeadline` for external calls.

### Logging
- You MUST use the following log levels: `Trace` (fine-grained debug), `Debug` (internal flow), `Info` (business events), `Warn` (recoverable), `Error` (unrecoverable). Where the project bridges Go logging into a platform logger with fewer levels, you MUST map onto the platform's levels per the project's documented logging convention.
- You MUST ALWAYS include identifiers in logs (request ID, entity ID, interface name, etc.).
- You MUST NEVER log secrets, tokens, API keys, key material, or PII.
- Errors MUST be actionable: include what failed, which identifiers, and likely next steps.

### Configuration
- You MUST NEVER hardcode secrets or environment-specific values.
- Full Go programs MUST use environment variables for configuration, parsed into strongly typed structs, validated at startup (fail fast). Go code embedded behind a fixed foreign ABI receives its configuration through that ABI's entry points — you MUST NOT invent a parallel env-var configuration channel for it.
- You MUST NOT hardcode, duplicate, or second-guess build-environment values (compilers, sysroots, target flags) that the project's build system supplies; the build system defined in `project.md` is authoritative.

### Modules & dependency management
- You MUST keep `go.mod` clean: run `go mod tidy` after adding or removing dependencies.
- You MUST ALWAYS commit both `go.mod` and `go.sum`.
- You MUST use latest stable versions of dependencies unless an in-use package requires an older release. Before adding something, ALWAYS check if it is the latest version.
- You MUST prefer well-maintained packages with active development.
- You MUST check for known vulnerabilities before adding: `govulncheck ./...`.
- You MUST prefer the Go standard library over third-party packages when feasible.
- The module location, the pinned Go toolchain, and any `replace` directives are project facts defined in `project.md`; run all `go` commands from the module directory it names. Any bump of a pinned/replaced dependency MUST leave `go mod tidy` with NO diff and `govulncheck` clean.

## 3) Testing Rules — ABSOLUTE RULES

All references to "tests" in this document mean automated tests (unit, integration, and e2e) that run during development and in CI/CD pipelines.

> **Cross-compiled cgo exemption:** purely mechanical cgo/`//export` glue that CANNOT run under host `go test` (because it only compiles for a foreign target platform) is exempt from the "tests are mandatory" rule ONLY to the extent it genuinely cannot be exercised on the host — you MUST extract any testable logic into plain Go and test THAT. Whether a project falls under this exemption is stated in `project.md`.

### General principles
- Tests are MANDATORY for all changes. There are ZERO exceptions (apart from the documented cross-compiled cgo exemption above).
- Tests MUST be small, focused, and non-redundant while still covering: happy path, edge cases, failure modes.
- Tests MUST ALWAYS pass.
- Tests MUST NOT depend on execution order.
- Tests MUST clean up after themselves (temp files, in-process servers, test containers).

### Frameworks — ABSOLUTE
- The standard library `testing` package is THE test framework. You MUST prefer the standard library (`t.Errorf`, `t.Fatalf`); use `testify/assert` / `testify/require` ONLY if already present in the module. You MUST NOT introduce third-party test dependencies into a module that has none.
- You MUST use **table-driven tests** as the default pattern for functions with multiple input/output cases; each test case MUST have a descriptive `name` field.
- You MUST use `t.Run(tc.name, func(t *testing.T) { ... })` for subtests.
- You MUST follow the **Arrange-Act-Assert** pattern consistently.
- You MUST mark test helpers with `t.Helper()`.
- You MUST name test functions descriptively: `TestServiceName_MethodName_Scenario`.

```go
func TestParseURL_Variants(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {name: "valid https URL", input: "https://example.com", want: "https://example.com", wantErr: false},
        {name: "empty string", input: "", want: "", wantErr: true},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            got, err := ParseURL(tc.input)
            if (err != nil) != tc.wantErr {
                t.Fatalf("ParseURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
            }
            if got != tc.want {
                t.Errorf("ParseURL(%q) = %q, want %q", tc.input, got, tc.want)
            }
        })
    }
}
```

### Test organization
- Test files MUST live next to the code they test: `foo.go` → `foo_test.go`.
- You MUST use the `_test` package suffix for black-box tests (e.g., `package foo_test`) to test only the public API.
- You MUST use the same package name only when you need to test unexported internals, and you MUST prefer this sparingly.
- Shared setup MUST be factored into test helpers; copy-pasted setup across test files is FORBIDDEN.

### Unit tests
- Unit tests MUST be fast (no I/O, no network, no external services).
- You MUST use interfaces and dependency injection to mock external dependencies.
- You MUST use `t.Parallel()` for tests that are safe to run concurrently.
- You MUST use `testing/fstest.MapFS` or `os.MkdirTemp` for filesystem-dependent tests.
- You MUST short-circuit with `t.Skip("reason")` or `-short` flag for tests that are too slow for rapid iteration.

### Integration tests
- Integration tests MUST verify that individual components work correctly against real external systems or real protocol surfaces (e.g., `net/http/httptest` servers speaking the real wire format, or in-process protocol harnesses).
- You MUST guard integration tests with the build tag `//go:build integration` at the top of the file.
- **Testcontainers are MANDATORY** when a test needs a real external service (DB, broker, …): it MUST use `testcontainers-go`. You MUST NEVER rely on pre-running Docker Compose services or shared, long-lived test infrastructure. A project with NO external-service infrastructure may document in `project.md` that testcontainers do not apply.
- You MUST start containers in `TestMain` or in a shared test helper and pass connection details to tests. You MUST use `t.Cleanup` (or `defer container.Terminate(ctx)`) to guarantee teardown.
- Containers MUST be ephemeral and isolated: each test suite gets its own container instance.
- Each integration test MUST set up and tear down its own state (use `t.Cleanup`).
- Integration tests MUST respect `context.Context` timeouts.

### End-to-end (E2E) tests
- E2E tests MUST exercise the full system roundtrip.
- You MUST guard E2E tests with the build tag `//go:build e2e`.
- All required infrastructure MUST be started via `testcontainers-go` (same rules and same documented-exception mechanism as integration tests). Where end-to-end behavior is validated by a consuming application or an upstream project instead of by Go e2e tests, `project.md` MUST say so.
- E2E tests MUST be idempotent and safe to re-run.
- You MUST use realistic but deterministic test data.

### Race detection
- Tests MUST run with the `-race` flag, locally and in CI: `go test -race ./...`.
- You MUST fix all data races immediately; they are not warnings — they are bugs.

### Mocking
- You MUST use interfaces for all external boundaries so they can be mocked in tests.
- You MUST prefer hand-written mocks (simple struct implementing the interface) for small interfaces.
- You MUST use code generation (`mockgen`, `moq`, or `counterfeiter`) only for interfaces with many methods.
- You MUST NEVER mock what you don't own in unit tests — you MUST wrap third-party clients behind your own interface first.

### Environment variables for tests
- Host-testable Go MUST run with a bare `go test` from the module directory; tests MUST NOT require ad-hoc environment setup unless `project.md` documents one.
- Values supplied by the project's build system for cross-compiled artifact builds MUST NOT be hardcoded, duplicated, or second-guessed in tests.

### Manual testing documentation
- Manual tests are NOT a substitute for automated tests.
- If manual testing steps are necessary, they MUST be clearly labeled as "**Manual Test**" or "**Manual QA Steps**" and documented separately from automated test descriptions.

## 4) Quality Gates — ABSOLUTE RULES

### Definition of Done
A change MUST be considered DONE **ONLY AND ONLY** if ALL are true:

- All relevant automated tests are written AND passing (any host-testable Go you add; see the cross-compiled cgo exemption in §3).
- **ZERO `go vet` / `golangci-lint` findings.** For cross-compiled cgo code, run the analysis in the cross-compile environment defined in `project.md`, or accept the project's documented compile gate as the authority.
- The Go artifact builds without errors or warnings via the project's standard build command (see `project.md` → Standard Commands).
- `go mod tidy` (run in the module directory) produces NO `go.mod`/`go.sum` diff.
- No TODOs, no commented-out dead code, no "temporary hacks".
- Changes are small, readable, and aligned with existing Go patterns.

### Fix broken tests — ABSOLUTE RULE
- You MUST fix ANY broken test, even if unrelated to your changes. Finish your current change first, then fix the broken test immediately.
- You MUST NEVER leave the test suite broken. There are ZERO exceptions.

### Fix broken linting — ABSOLUTE RULE
- You MUST fix ANY linting or formatting error, even if unrelated to your changes. Finish your current change first, then fix the violations immediately.
- You MUST NEVER leave the codebase with linting or formatting violations. There are ZERO exceptions.

### No linting suppression — ABSOLUTE RULE
- You MUST NEVER suppress, silence, or skip linting rules (e.g., `//nolint` directive comments, `exclude`/`exclude-rules` entries in the golangci-lint config, baseline files) to make errors disappear.
- You MUST FIX the root cause of every linting error or warning by adjusting the implementation.
- The ONLY exception is when a linting rule GENUINELY and unavoidably conflicts with the project's documented design decisions. In that case, you MUST explain the conflict to the user and get EXPLICIT approval before adding any suppression. This is NON-NEGOTIABLE.

### Standard build/lint/test commands
- The authoritative command surface (module directory, build command, vet/lint invocation, tidy, vulncheck) is defined in `project.md` → Standard Commands. You MUST use those commands — NEVER ad-hoc ones.
- **Format:** `gofmt -l -w .` / `goimports` (source-only, runs standalone).
- **Tidy:** `go mod tidy` (source-only, runs standalone).
- **Vulnerabilities:** `govulncheck ./...`.
