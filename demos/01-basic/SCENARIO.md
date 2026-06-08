# Demo 01 - Basic Set-Cookie audit

A realistic HTTP response dump (`response_dump.txt`) captured from a login
endpoint you own. It contains four `Set-Cookie` headers with a mix of good and
bad hardening:

- `__Host-session` — session id, but **missing Secure** (violates the
  `__Host-` prefix contract) — high severity.
- `auth_token` — auth token with **no HttpOnly and no SameSite** — escalated
  because the name looks sensitive.
- `tracking` — `SameSite=None` **without Secure**, which modern browsers
  reject — high severity.
- `theme` — a benign UI preference cookie that is mostly fine.

## Run it

```sh
# Human-readable table (exits non-zero because of medium+ findings)
python -m cookieaudit audit demos/01-basic/response_dump.txt

# JSON for pipelines / CI
python -m cookieaudit audit demos/01-basic/response_dump.txt --format json

# Shareable self-contained HTML report (the tool's UI)
python -m cookieaudit audit demos/01-basic/response_dump.txt \
    --format html -o report.html
```

Expected: several findings including `host-prefix-violation` and
`samesite-none-insecure` at HIGH severity, and a non-zero exit code.
