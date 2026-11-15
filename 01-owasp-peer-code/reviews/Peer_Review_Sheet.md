Reviewer pair: [your names]      Code authored by: [author's names]      Date: 11/15/26
| Check | Pass? | Note |
|-------|-------|------|
| All 6 risks found & correctly named | Y | All six map to the OWASP 2025 names (A01, A02, A04, A05, A07, A10). Minor: A10 is officially "Mishandling of Exceptional Conditions". |
| Every fix block its attack (tested) | N | A07 fix is bypassable: the hardcoded fallback `SECRET_KEY` let me forge an admin token (200 on `/admin/users`). Login timing also reveals valid usernames (~2 ms unknown vs ~33 ms known). |
| App still works (register/login/notes) | Y | All 5 provided tests pass; register, login, list/create/read notes all work. |
| No plaintext passwords stored/password | Y | Passwords are salted PBKDF2-HMAC-SHA256 with constant-time compare. Nit: 100,000 iterations is low (OWASP suggests ~600,000). |
| No secret / stack trace left in code | N | `SECRET_KEY` default is hardcoded in `main.py` and the repo will be public. The 500 handler hides stack traces correctly. |
| Permission checks fail closed | Y | Missing/invalid token -> 401, non-admin -> 403. Caveat: admins can read any user's note, which contradicts FINDINGS.md row 1. |

1 strength: Clean OOP structure (repository + security service) and every SQL query is parameterized.

1 must-fix: Remove the hardcoded `SECRET_KEY` default (load from the environment or generate a random one) so tokens cannot be forged; also run a dummy hash for unknown usernames so login timing is uniform.

1 suggestion: Use `Depends(current_user)` / a `require_admin` dependency instead of calling auth by hand in each route, remove the admin override on `GET /notes/{id}`, and raise PBKDF2 iterations to ~600,000.
