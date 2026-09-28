# ATS — Engineering Q&A Index

Answers to every "Explain" gate question across all sprints, organised by concept domain.
Each answer documents the *reasoning* behind the implementation decision — not just what the code does, but why.

Use for: interview prep · design reviews · onboarding · code review reference.

---

## Files

| File | Domain | Contributing STs |
|------|--------|-----------------|
| [`ATS-QA-Security.md`](ATS-QA-Security.md) | RSA keys, JWKS, JWT claims, token signing | ST-3, ST-7, ST-8 |
| [`ATS-QA-Data-Layer.md`](ATS-QA-Data-Layer.md) | Schema design, migrations, repository patterns, transactions | ST-4, ST-5 |
| [`ATS-QA-Resilience.md`](ATS-QA-Resilience.md) | Redis failure modes, race conditions, startup failures, graceful shutdown | ST-6, ST-8, ST-9 |
| [`ATS-QA-Auth-Flows.md`](ATS-QA-Auth-Flows.md) | Password grant, client credentials, refresh rotation, revocation, error handling | ST-8 |
| [`ATS-QA-Operations.md`](ATS-QA-Operations.md) | Structured logging, 12-factor config, Docker, test design | ST-1, ST-2, ST-10, ST-11 |

---

## Completion Status

| File | Status |
|------|--------|
| `ATS-QA-Operations.md` | ST-1 questions answered · ST-2, ST-10, ST-11 pending |
| `ATS-QA-Security.md` | Pending |
| `ATS-QA-Data-Layer.md` | Pending |
| `ATS-QA-Resilience.md` | Pending |
| `ATS-QA-Auth-Flows.md` | Pending |

---

## How This Document Grows

After each ST clears its Explain gate, the answers are written into the relevant file(s) above.
A question may appear in more than one file if it spans domains — e.g. "Why store the token hash?" appears in both Security (hash prevents plaintext exposure) and Data Layer (hash as the lookup key).

See [`auth-token-server-sprints.md`](../../auth-token-server-sprints.md) for the full list of Explain questions per ST.
