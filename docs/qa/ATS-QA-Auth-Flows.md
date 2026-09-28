# ATS — Q&A: Auth Flows

Covers the end-to-end logic of each grant flow, token rotation, and revocation.

**Contributing STs:** ST-8 (HTTP Handlers)

---

## Password Grant

---

**Q: A user submits correct credentials but their account is marked `disabled=true` — what should happen and at which layer?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: Why is bcrypt used for password hashing instead of SHA-256 or SHA-512?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: The password grant returns both an access token and a refresh token. Why not just return a long-lived access token?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## Client Credentials Grant

---

**Q: How is the client credentials grant different from the password grant from a security perspective?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: A service account's `client_secret` is compromised — what is the remediation path? What does the ATS need to support for this?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## Refresh Token Rotation

---

**Q: Walk through the full refresh token rotation flow step by step.**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: Why is the refresh token rotated on every use instead of being long-lived and reusable?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: A client receives a new refresh token but fails to persist it (crashes before saving). What happens on the next request?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: Why does the rotation flow check expiry from the Postgres record rather than relying on the Redis TTL?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## Revocation

---

**Q: Walk through the revocation flow — what happens in Postgres, what happens in Redis, and in what order?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: A `POST /auth/revoke` request succeeds in Postgres but Redis `SetRevoked` fails — is the token revoked? What happens if the same token is used in a refresh request before Redis is back?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## Error Handling

---

**Q: Why do all error responses use `{ "error": "...", "error_description": "..." }` instead of a custom shape?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: A completely malformed JSON body is sent to `POST /auth/token` — what HTTP status and body does the client receive?**

*Answer will be added after ST-8 Explain gate is passed.*

---

**Q: Why does an invalid credential attempt return `401` and not `403`?**

*Answer will be added after ST-8 Explain gate is passed.*
