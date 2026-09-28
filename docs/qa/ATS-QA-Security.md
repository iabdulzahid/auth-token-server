# ATS — Q&A: Security

Covers RSA key management, JWKS, JWT design, and token signing decisions.

**Contributing STs:** ST-3 (RSA Keys + JWKS), ST-7 (Token Minting), ST-8 (downstream token validation)

---

## RSA Key Management

---

**Q: Why is RS256 used instead of HS256?**

*Answer will be added after ST-7 Explain gate is passed.*

---

**Q: Why is `kid` derived from a SHA-256 thumbprint of the public key rather than randomly generated?**

*Answer will be added after ST-3 Explain gate is passed.*

---

**Q: What happens if the `kid` in the JWKS does not match the `kid` in the JWT header?**

*Answer will be added after ST-3 Explain gate is passed.*

---

**Q: What happens if `RSA_PRIVATE_KEY_PEM` is set but contains a garbage value?**

*Answer will be added after ST-3 Explain gate is passed.*

---

## JWKS and Downstream Validation

---

**Q: Why do downstream services validate JWTs locally using JWKS instead of calling the ATS on every request?**

*Answer will be added after ST-3 Explain gate is passed.*

---

**Q: A downstream service receives a JWT signed with an old key after key rotation — what happens?**

*Answer will be added after ST-8 Explain gate is passed.*

---

## JWT Claims Design

---

**Q: What does the `jti` claim prevent?**

*Answer will be added after ST-7 Explain gate is passed.*

---

**Q: Why is `scope` embedded in the JWT as a space-separated string rather than a JSON array?**

*Answer will be added after ST-7 Explain gate is passed.*

---

**Q: Why is the `sub_type` claim needed? What breaks if you remove it?**

*Answer will be added after ST-7 Explain gate is passed.*

---

## Refresh Token Security

---

**Q: Why do we store the SHA-256 hash of the refresh token instead of the raw value?**

*Answer will be added after ST-7 Explain gate is passed.*

---

**Q: Why is the raw refresh token generated with `crypto/rand` and not `math/rand`?**

*Answer will be added after ST-7 Explain gate is passed.*
