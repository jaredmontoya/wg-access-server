# AGENTS.md

## Project Overview

WireGuard VPN access server with a web UI. Go 1.24 backend (gRPC, gorilla/mux HTTP)
with a React/TypeScript frontend (Vite, MUI, MobX). Protobuf for API definitions.
Module path: `github.com/freifunkMUC/wg-access-server`

## Build Commands

```bash
# Go backend
go build -o wg-access-server
go generate buildinfo/buildinfo.go && go build -o wg-access-server   # with version info

# Frontend (website/)
cd website
npm ci                # Install dependencies
npm run build         # Type-check (tsc) + Vite build, outputs to website/build/
npm run start         # Dev server on port 3000 with API proxy to localhost:8000

# Protobuf codegen
./codegen.sh                          # Go protobuf generation
cd website && npm run codegen         # TypeScript gRPC-web stubs
```

## Test Commands

```bash
# Run all Go tests
go test -v ./...

# Run tests in a single package
go test -v ./internal/storage/
go test -v ./internal/dnsproxy/
go test -v ./pkg/authnz/authconfig/

# Run a single test by name
go test -v -run TestMemoryStorage ./internal/storage/
go test -v -run Test_evaluateClaimMapping ./pkg/authnz/authconfig/
go test -v -run TestDNSProxy_ServeDNS ./internal/dnsproxy/
```

## Lint Commands

```bash
# Go linting (golangci-lint v2)
golangci-lint run --timeout 4m

# Frontend linting
cd website && npm run lint

# Frontend formatting
cd website && npm run prettier

# Spell checking (requires typos CLI)
typos
```

## Code Style Guidelines

### Go

#### Imports
Three groups separated by blank lines, in order:
1. Standard library
2. Third-party packages (alphabetical)
3. Internal project packages (`github.com/freifunkMUC/wg-access-server/...`)

```go
import (
    "fmt"
    "os"

    "github.com/pkg/errors"
    "github.com/sirupsen/logrus"

    "github.com/freifunkMUC/wg-access-server/internal/storage"
)
```

Blank-import side-effect imports (e.g., DB drivers) are grouped with their parent.

#### Error Handling
- Use `github.com/pkg/errors` for wrapping: `errors.Wrap(err, "context message")`
  and `errors.Wrapf(err, "failed for %s", val)` -- NOT `fmt.Errorf("%w", err)`
- `errors.New("message")` for simple errors
- gRPC services return `status.Errorf(codes.X, "message")`
- Top-level orchestration code uses `logrus.Fatal()` or `logrus.Error()` instead of returning
- `errcheck` is allowed to be skipped on `defer` statements

#### Naming
- **Packages**: lowercase, single or concatenated words (`authconfig`, `dnsproxy`, `authnz`)
- **Files**: lowercase with underscores (`device_service.go`, `api_router.go`)
- **Exported types/functions**: PascalCase (`DeviceManager`, `NewSqlStorage`)
- **Unexported types/functions**: camelCase (`servecmd`, `pgconn`, `mapDevice`)
- **Receivers**: single letter matching the type (`d` for `DeviceManager`, `s` for `SQLStorage`)
- **Variables**: short idiomatic Go (`ctx`, `err`, `wg`, `s`, `r`, `w`)
- **Acronyms**: kept uppercase (`CIDR`, `MTU`, `DNS`, `OIDC`, `HTTP`)
- **Constructors**: `New()` or `New<TypeName>()` pattern

#### Logging
- Use `github.com/sirupsen/logrus` (global functions, no passed-around logger instances)
- Levels: `Fatal` (unrecoverable startup), `Error` (operational), `Warn` (degraded),
  `Info` (normal events), `Debug` (diagnostics)
- Structured fields via `logrus.WithFields(logrus.Fields{...})`
- gRPC handlers use `ctxlogrus.Extract(ctx)` for context-aware logging
- Request tracing via `traces.Logger(ctx)` which adds `trace.id`

#### Types and Interfaces
- Small, behavior-focused interfaces (e.g., `Storage`, `Watcher`, `Pingable`)
- Interface composition: embed smaller interfaces into larger ones
- `Opts` or `Config` structs for constructor parameters
- Define interfaces in `contracts.go`, implementations in separate files
- Use struct embedding for interface partial implementation

#### Testing
- Use `testing` stdlib and `github.com/stretchr/testify/require`
- testify pattern: `require := require.New(t)` then `require.NoError(err)`
- Table-driven tests with `tests := []struct{ name string; ... }{ ... }` and `t.Run(tt.name, ...)`
- Test naming: `TestSubject`, `Test_unexportedFunc`, `TestType_Method`
- `reflect.DeepEqual` is used in some older tests (prefer testify assertions for new code)

### TypeScript/React (website/)

#### Formatting (Prettier)
- Semicolons: yes
- Trailing commas: all
- Single quotes: yes
- Print width: 120
- Tab width: 2

#### Architecture
- Class components with MobX `observer()` HOC (no functional components/hooks)
- Pattern: `export const X = observer(class X extends React.Component<Props> { ... })`
- Global state via `AppState` singleton using `makeObservable`
- State mutations wrapped in `runInAction(() => { ... })`
- API calls via gRPC-web generated client (`grpc.server`, `grpc.users`, `grpc.devices`)

## Project Structure

- `main.go` -- CLI entrypoint (kingpin)
- `cmd/` -- CLI subcommands (serve, migrate)
- `internal/config/` -- AppConfig with yaml tags
- `internal/devices/` -- Device management business logic
- `internal/dnsproxy/` -- Embedded DNS proxy server
- `internal/network/` -- IP allocation, iptables, VPN networking
- `internal/services/` -- HTTP/gRPC service layer (API boundary)
- `internal/storage/` -- Persistence (SQL via GORM, in-memory)
- `internal/traces/` -- Request tracing
- `pkg/authnz/` -- Auth subsystem (OIDC, basic, session, middleware)
- `proto/` -- .proto definitions + generated .pb.go code
- `website/` -- React/TypeScript frontend (Vite)
- `buildinfo/` -- Build version/commit metadata

## CI Workflows (.github/workflows/)

| Workflow | Trigger | Action |
|---|---|---|
| test.yml | push/PR to master | `go test -v ./...` |
| linting.yml | push/PR to master | `gitleaks` + `golangci-lint` v2.5 |
| build.yml | push/PR to master | Docker multi-stage build (no push) |
| publish.yml | push to master/tags | Build + push to `ghcr.io` (multi-arch) |
| typos.yml | push/PR/cron | Spell checking with `typos` |
