# TestApp

**Author:** Gülşah Şahin — Gazi University, Faculty of Engineering, Computer Engineering Department
**Course:** BM496 Graduation Project (2025–2026 Spring)

Deliberately vulnerable Flask application used as the controlled target for the [VULCAN](../vulcan/README.md) scanner. Provides the **ground truth** required to compute Precision / Recall / F1 for the project's validation chapter.

This component implements SRS section 3 (FG-TA-01 → FG-TA-06) and SDD §3.1.1 / §4.3.

## Role in the project

```
Browser ──HTTP──▶ VULCAN proxy ──HTTP──▶ TestApp:5001
                                            │
                                            ▼
                                  ground_truth.jsonl
                                  (one record per request,
                                   keyed by X-Vulcan-Trace-Id)
```

Each incoming request's `X-Vulcan-Trace-Id` header is logged together with the user/role, path, and status code. VULCAN findings are correlated with these records via the same Trace-ID to objectively measure detection accuracy.

## Setup

```bash
cd testapp
uv sync
```

## Run

```bash
./run.sh
```

or:

```bash
uv run python -m testapp.app
```

The app listens on `http://localhost:5001`.

The ground-truth log path defaults to `src/testapp/ground_truth.jsonl` and can be overridden:

```bash
export TESTAPP_GROUND_TRUTH_LOG=/tmp/vulcan_ground_truth.jsonl
```

## Web pages (for manual demos)

| Path | Purpose |
|---|---|
| `/` | Login |
| `/profile` | Profile (IDOR target) |
| `/orders` | Orders (IDOR target) |
| `/cart` | Cart (IDOR target) |
| `/products` | Public listing |
| `/admin` | Admin panel (privilege-escalation target) |

## Test users

| Username | Password | Role |
|---|---|---|
| alice | `password123` | user |
| bob | `password456` | user |
| charlie | `password789` | user |
| admin | `admin123` | admin |

## Intentional vulnerabilities

### Horizontal IDOR (FG-TA-03)
- `GET  /api/profile?id=<other_user>` — query parameter overrides session
- `PUT  /api/profile` — accepts arbitrary `user_id` in body
- `GET  /api/orders?user_id=<other_user>` — listing scoped by parameter, not session
- `GET  /api/orders/<order_id>` — no ownership check
- `DELETE /api/orders/<order_id>` — no ownership check
- `GET  /api/cart?cart_id=<other_user>` — cart accessed by parameter override

### Privilege escalation (FG-TA-01)
- `GET    /api/admin/users` — admin-only listing (should reject non-admins)
- `DELETE /api/admin/users/<user_id>` — admin-only deletion

### SQL-injection surface (FG-TA-04)
- `GET /api/search?q=...` — parameter is reflected (extension point for SQLi payloads)

### Static resources (FG-TA-05)
- `/static/app.js`, `/static/style.css`

## Ground-truth log (FG-TA-06)

Every request triggers an `after_request` hook that appends a JSON line of the form:

```json
{
  "trace_id": "8b1c…",
  "timestamp_ms": 1735000000123,
  "method": "GET",
  "path": "/api/profile",
  "status_code": 200,
  "user_id": "1",
  "role": "user"
}
```

Requests without an `X-Vulcan-Trace-Id` header (i.e., not routed through VULCAN) are skipped, keeping the log focused on scan traffic.

The reference test corpus is committed at `vulcan/tests/data/ground_truth.jsonl` and lists ten labeled scenarios used by the validation scripts.

## Test scenarios (used by `vulcan/scripts/full_validation.py`)

1. Login as **alice**, then `GET /api/profile?id=2` → IDOR (should be flagged)
2. Login as **alice**, then `GET /api/profile` → clean baseline
3. Login as **alice**, then `PUT /api/profile` with `user_id=2` → IDOR
4. Login as **alice**, then `GET /api/orders?user_id=2` → IDOR
5. Login as **alice**, then `GET /api/orders/3` → IDOR
6. Login as **alice**, then `DELETE /api/orders/3` → IDOR
7. Login as **alice**, then `GET /api/cart?cart_id=2` → IDOR
8. Login as **alice**, then `GET /api/admin/users` → 403, **not** vulnerable
9. `GET /api/products` (anonymous) → public, **not** vulnerable
10. Login as **alice**, then `GET /api/cart` → own cart, **not** vulnerable

These scenarios mix true positives, true negatives, and edge cases so the resulting Precision / Recall / F1 numbers are meaningful.
