# ATS — Q&A: Resilience

Covers failure modes, degraded operation, race conditions, and system behaviour under adverse conditions.

**Contributing STs:** ST-6 (Redis Cache), ST-8 (Refresh Handler), ST-9 (Startup Wiring)

---

## Redis Failure Modes

---

**Q: Redis is down — what happens to a refresh request?**

*Answer will be added after ST-6 Explain gate is passed.*

---

**Q: Redis says `revoked=true` — why can we reject the token without querying Postgres?**

*Answer will be added after ST-6 Explain gate is passed.*

---

**Q: Redis says `revoked=false` (explicit cache entry saying not revoked) — why do we still query Postgres?**

*Answer will be added after ST-6 Explain gate is passed.*

---

**Q: Redis is flushed completely (all keys deleted) — what is the impact on the running system?**

*Answer will be added after ST-6 Explain gate is passed.*

---

**Q: `SetRevoked` fails after a successful Postgres revocation — is the token now revocable? What happens on the next refresh attempt?**

*Answer will be added after ST-6 Explain gate is passed.*

---

**Q: Why does `NewCache` log a warning instead of returning a fatal error when Redis is unreachable at startup?**

*Answer will be added after ST-6 Explain gate is passed.*

---

## Concurrent Request Race Conditions

---

**Q: Two refresh requests arrive simultaneously with the same refresh token — what prevents both from succeeding?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: What is a TOCTOU (Time-of-Check Time-of-Use) bug? Where would it occur in the refresh flow without `SELECT FOR UPDATE`?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: Why is the old token revocation and the new token insertion done in a single transaction rather than two separate queries?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## Startup Failure Modes

---

**Q: Postgres is unreachable at startup — does the service start or crash? Why?**

*Answer will be added after ST-9 Explain gate is passed.*

---

**Q: Redis is unreachable at startup — does the service start or crash? Why is this different from Postgres?**

*Answer will be added after ST-9 Explain gate is passed.*

---

**Q: A migration fails halfway through — what state is the database in? What happens on the next startup?**

*Answer will be added after ST-9 Explain gate is passed.*

---

## Graceful Shutdown

---

**Q: What is the purpose of graceful shutdown? What goes wrong without it?**

*Answer will be added after ST-9 Explain gate is passed.*

---

**Q: Why is the shutdown drain timeout 10 seconds and not infinite?**

*Answer will be added after ST-9 Explain gate is passed.*
