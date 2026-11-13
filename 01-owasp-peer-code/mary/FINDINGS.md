# Vulnerability Findings — Web Systems & Technologies Lab 1

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

| # | OWASP 2025 code & name | Where (route / line) | How an attacker abuses it | Your fix (1 line) |
|---|------------------------|----------------------|---------------------------|-------------------|
| 1 | A01 Broken Access Control | `GET /notes/{note_id}` (line 133) | Any authenticated user can read other users' private notes simply by changing the `note_id` in the URL. | Validate that `note.owner_id == user.id` before returning note data, returning HTTP 403 Forbidden otherwise. |
| 2 | A02 Security Misconfiguration | CORS middleware & global error handler (lines 31–37, 94–99) | Overly permissive `allow_origins=["*"]` with credentials enabled, plus uncaught exception handler returning raw `traceback.format_exc()` exposing server internals. | Restrict CORS origins to trusted domains and sanitize exception responses to return generic 500 error messages without stack traces. |
| 3 | A04 Cryptographic Failures | Database seed & `POST /register` (lines 50, 63–65, 107) | Passwords stored and retrieved in cleartext directly in SQLite; database compromise immediately exposes all user credentials. | Salt and hash passwords using PBKDF2-HMAC-SHA256 upon registration/seeding, and verify in constant time using `hmac.compare_digest`. |
| 4 | A05 Injection | `POST /login` (lines 115–117) | User input was formatted directly into a raw SQL string (`f"SELECT id, password FROM users WHERE username = '{creds.username}'"`), allowing SQL injection (e.g. `' OR '1'='1`). | Use parameterized SQL queries (`WHERE username = ?`) so input is treated strictly as data. |
| 5 | A07 Authentication Failures | `POST /login` & `current_user` (lines 88–90, 118–122) | Sequential predictable user IDs used as bearer tokens without signing or expiration; distinct error messages ("No account..." vs "Wrong password") allowed username enumeration. | Issue tamper-proof cryptographically signed (HMAC) tokens with expiration timestamps, and return uniform generic error messages ("Invalid credentials"). |
| 6 | A10 Exceptional Conditions | `GET /admin/users` (lines 155–159) | Authorization check wrapped in `try...except` that swallowed errors with `pass`, failing open and executing admin logic even when permissions were invalid or failed. | Enforce fail-closed authorization checks that raise HTTP 403 when user is not admin or when evaluation errors occur. |

## Reflection (3–4 sentences)
Which bug would do the most damage in a real app, and why?

In a real-world web application, **A05: Injection** and **A04: Cryptographic Failures** present the most catastrophic risks because SQL injection allows an attacker to completely bypass authentication, dump or alter entire databases, and execute arbitrary database commands. Paired with plaintext password storage, an attacker who extracts the database gains immediate, permanent access to user credentials across services without needing to crack hashes. Parameterized queries and industry-standard password hashing (PBKDF2/bcrypt) form the foundational layer of web defense required before any endpoint can be considered safe.
