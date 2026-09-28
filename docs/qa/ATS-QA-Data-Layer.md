# ATS — Q&A: Data Layer

Covers PostgreSQL schema design, migration strategy, repository patterns, and transaction behaviour.

**Contributing STs:** ST-4 (Schema + Migrations), ST-5 (Store Layer)

---

## Schema Design

---

**Q: Why is `token_hash` stored instead of the raw refresh token value?**

*Answer will be added after ST-5 Explain gate is passed.*

---

**Q: Why does `refresh_tokens` have both a `revoked` boolean column and an `expires_at` timestamp? Isn't one enough?**

*Answer will be added after ST-4 Explain gate is passed.*

---

**Q: Why is `subject_type` a text column rather than a foreign key to both `users` and `service_accounts`?**

*Answer will be added after ST-4 Explain gate is passed.*

---

**Q: Why are `scopes` stored as a `text[]` array on the token row instead of joining back to the user's scopes at validation time?**

*Answer will be added after ST-4 Explain gate is passed.*

---

## Migrations

---

**Q: What happens if the service crashes mid-migration?**

*Answer will be added after ST-4 Explain gate is passed.*

---

**Q: Why do we track applied migrations by filename instead of a version number?**

*Answer will be added after ST-4 Explain gate is passed.*

---

**Q: Why are migrations run at startup rather than as a separate pre-deploy step?**

*Answer will be added after ST-4 Explain gate is passed.*

---

**Q: Running migrations twice — what happens? Why?**

*Answer will be added after ST-4 Explain gate is passed.*

---

## Repository and Transaction Patterns

---

**Q: Why does `GetRefreshTokenByHashForUpdate` exist as a separate function from `GetRefreshTokenByHash`?**

*Answer will be added after ST-5 Explain gate is passed.*

---

**Q: What happens if two goroutines call `InsertRefreshToken` with the same hash simultaneously?**

*Answer will be added after ST-5 Explain gate is passed.*

---

**Q: Why do repository functions accept `context.Context` as their first argument?**

*Answer will be added after ST-5 Explain gate is passed.*

---

**Q: Why is there no raw SQL outside the `store` package?**

*Answer will be added after ST-5 Explain gate is passed.*
