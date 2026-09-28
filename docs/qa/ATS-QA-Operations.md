# ATS — Q&A: Operations

Covers configuration, structured logging, Docker, startup wiring, and test design.

**Contributing STs:** ST-1 (Scaffolding), ST-2 (Config), ST-10 (Docker), ST-11 (Tests)

---

## Configuration

---

**Q: Why does `main.go` use `slog.NewJSONHandler(os.Stdout, nil)` instead of the default `slog.Default()`?**

`slog.Default()` uses a text handler writing to stderr — readable on a terminal but unparseable by log aggregators in production. `slog.NewJSONHandler(os.Stdout, nil)` emits structured JSON to stdout for three reasons:

1. **Stdout over stderr** — 12-factor apps treat logs as an event stream on stdout. Container runtimes (Docker, Kubernetes) capture stdout and forward it to the log aggregator. Stderr is reserved for unrecoverable process-level errors.

2. **JSON over text** — A text line like `INFO token issued subject=abc ttl=15m` is a string a human can read but a machine cannot reliably parse. A JSON line like `{"level":"INFO","msg":"token issued","subject":"abc","ttl":"15m"}` is structured data — every field is individually indexable, queryable, and alertable in any log aggregator.

3. **Consistent from day one** — every subsequent `slog.Info(...)` call anywhere in the codebase automatically produces machine-readable output. Retrofitting structure into a text-log codebase later is expensive and error-prone.

**Rule of thumb:** In a 12-factor service, logs go to stdout as structured JSON. The runtime decides where they end up, not the application.

---

**Q: Why create the directory skeleton before writing any code?**

An empty but correctly structured project has a clear contract with every contributor before a single line of logic exists:

- `internal/` — Go enforces at the compiler level that packages under `internal/` are not importable by external modules. It is a visibility boundary, not just a naming convention.
- `cmd/ats/` — signals a runnable binary, not a library. Go community convention; any experienced Go engineer immediately knows where `main` lives.
- `migrations/` at the root — signals schema management is first-class, not an afterthought.

Starting with structure also prevents the common mistake of writing code first and reorganising later — which requires changing import paths, breaking in-progress work, and rewriting test setup.

---

**Q: Why collect all missing config errors instead of failing on the first?**

*Answer will be added after ST-2 Explain gate is passed.*

---

**Q: Why is there a hard rule against `os.Getenv` calls outside `internal/config`?**

*Answer will be added after ST-2 Explain gate is passed.*

---

**Q: Why are defaults for optional fields baked into `Load()` rather than leaving it to callers?**

*Answer will be added after ST-2 Explain gate is passed.*

---

**Q: What happens if `RSA_PRIVATE_KEY_PEM` is set but contains a garbage value (not a valid PEM block)?**

*Answer will be added after ST-2 Explain gate is passed.*

---

## Docker and Local Development

---

**Q: Why do we copy `migrations/` into the final Docker image?**

*Answer will be added after ST-10 Explain gate is passed.*

---

**Q: The `ats` container starts before Postgres is ready — what happens?**

*Answer will be added after ST-10 Explain gate is passed.*

---

**Q: Why use a multi-stage Dockerfile instead of a single stage?**

*Answer will be added after ST-10 Explain gate is passed.*

---

**Q: Why does the final image use `alpine` rather than the `golang` base image?**

*Answer will be added after ST-10 Explain gate is passed.*

---

## Test Design

---

**Q: What does a given unit test actually prove? What does it deliberately not prove?**

*Answer will be added after ST-11 Explain gate is passed.*

---

**Q: Why generate the RSA key inside the test instead of using a hardcoded test key?**

*Answer will be added after ST-11 Explain gate is passed.*

---

**Q: What scenarios are NOT covered by the current unit tests? What would integration tests cover that unit tests cannot?**

*Answer will be added after ST-11 Explain gate is passed.*

---

**Q: Why use `t.Setenv` in config tests instead of `os.Setenv`?**

*Answer will be added after ST-11 Explain gate is passed.*
