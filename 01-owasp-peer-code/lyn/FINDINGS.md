# Vulnerability Findings — Lyn & Mary

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A01 Broken Access Control | `GET /notes/{note_id}` (`get_note`) | Any logged-in user changes the ID in the URL (e.g. `/notes/2`) and reads another user's private note (IDOR). | Compare `note.owner_id` to the caller's ID and return 403 if they differ, with no admin exception. |
| 2 | A02 Security Misconfiguration | CORS middleware and the global error handler | CORS allowed any origin (`*`) together with credentials, so any website could call the API as the user; error responses returned full stack traces that exposed internals. | Allow only trusted origins and `GET`/`POST`; return a generic 500 message and log the real error on the server only. |
| 3 | A04 Cryptographic Failures | Seed data and `POST /register` | Passwords were stored in plaintext, so anyone who gets the database has every user's password. | Store salted PBKDF2-HMAC-SHA256 hashes (about 600,000 iterations) and check them with `hmac.compare_digest`. |
| 4 | A05 Injection | `POST /login` | Username was pasted into a raw SQL string, so input like `' OR '1'='1' --` logs the attacker in without a password. | Use parameterized queries (`WHERE username = ?`) so input is always treated as data. |
| 5 | A07 Authentication Failures | `POST /login` and `current_user` | The token was just the user ID, so anyone could guess or forge one; different error messages (and response time) revealed which usernames exist. | Issue HMAC-signed tokens with an expiry, take the secret from an environment variable, return one generic error, and hash a dummy password for unknown users. |
| 6 | A10 Mishandling of Exceptional Conditions | `GET /admin/users` | The admin check was wrapped in a `try/except` that swallowed errors, so the route failed open and ran the admin code anyway. | Use a `require_admin` dependency that denies by default and raises 403 for non-admins. |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

A05: Injection would do the most damage because one unsafe query lets an attacker skip the login entirely and often read, change, or delete the whole database. It also makes every other defence pointless, since the attacker never has to guess a password or forge a token. Unlike a bug in a single route, it can expose all users' data at once. The fix is cheap, which is why parameterized queries should be the first thing checked in any code review.

## Added after peer review
- The signing secret must not be hardcoded in the source; load it from the `SECRET_KEY` environment variable.
- Admins get no override on other users' notes; ownership is strict.
- Login does the same hashing work for unknown users so timing does not leak which usernames exist.