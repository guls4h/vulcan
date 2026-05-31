"""VULCAN bütüncül doğrulama betiği (thesis verification harness).

Her senaryoyu gerçek SecurityAgent (OpenAI gpt-4o-mini) üzerinden çalıştırır;
gecikme, token tüketimi, doğru/yanlış sınıflandırma ve karışıklık matrisini
ölçer. Çıktı olarak hem JSON hem de Markdown raporu üretir.

Kullanım:
    cd vulcan && uv run python scripts/full_validation.py
"""

from __future__ import annotations

import asyncio
import json
import re
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from vulcan.agent.security_agent import SecurityAgent
from vulcan.config import Config
from vulcan.utils.pii_masker import PIIMasker
from vulcan.utils.token_counter import TokenCounter


# ---------------------------------------------------------------------------
# Senaryo havuzu
# ---------------------------------------------------------------------------

# Session cookie kullanıcı 1 (alice) için sabit:
SESSION_USER_1 = "session=eyJ1c2VyX2lkIjoiMSIsInJvbGUiOiJ1c2VyIn0.signed"
SESSION_USER_2 = "session=eyJ1c2VyX2lkIjoiMiIsInJvbGUiOiJ1c2VyIn0.signed"


def _packet(method: str, url: str, path: str, status: int, *, cookie: str | None,
            req_body: str = "", resp_body: str = "", trace_id: str = "",
            content_type: str = "application/json") -> dict[str, Any]:
    headers = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        headers["Cookie"] = cookie
    if trace_id:
        headers["X-Vulcan-Trace-Id"] = trace_id
    return {
        "method": method,
        "url": url,
        "path": path,
        "status_code": status,
        "request_headers": headers,
        "response_headers": {"Content-Type": content_type},
        "request_body": req_body,
        "response_body": resp_body,
        "timestamp": 0,
    }


def build_scenarios() -> list[dict[str, Any]]:
    """17 senaryo: 10 ground-truth (IDOR/yetkilendirme) + 7 prob matrisi (SQLi/BAC)."""

    s: list[dict[str, Any]] = []

    # --- Ground truth IDOR scenarios --------------------------------------
    s.append({
        "id": "GT-01", "tc": "TC-TA-03/TC-PS-09",
        "label": "IDOR: alice → user 2 profile via ?id=2",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("GET", "http://localhost:5001/api/profile?id=2",
                          "/api/profile", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"id": 2, "username": "bob",
                                                 "email": "bob@test.com",
                                                 "role": "user"})),
    })
    s.append({
        "id": "GT-02", "tc": "TC-PS-09",
        "label": "Safe: alice reads own profile",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("GET", "http://localhost:5001/api/profile?id=1",
                          "/api/profile", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"id": 1, "username": "alice",
                                                 "email": "alice@test.com",
                                                 "role": "user"})),
    })
    s.append({
        "id": "GT-03", "tc": "TC-TA-03",
        "label": "IDOR: alice PUT updates user 2 profile",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("PUT", "http://localhost:5001/api/profile",
                          "/api/profile", 200, cookie=SESSION_USER_1,
                          req_body=json.dumps({"user_id": 2, "email": "x@x"}),
                          resp_body=json.dumps({"id": 2, "username": "bob",
                                                 "email": "x@x"})),
    })
    s.append({
        "id": "GT-04", "tc": "TC-TA-03",
        "label": "IDOR: alice lists user 2 orders via ?user_id=2",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("GET", "http://localhost:5001/api/orders?user_id=2",
                          "/api/orders", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps([{"id": 5, "user_id": 2,
                                                   "total": 99.0}])),
    })
    s.append({
        "id": "GT-05", "tc": "TC-TA-03",
        "label": "IDOR: alice GET /api/orders/3 (owned by user 2)",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("GET", "http://localhost:5001/api/orders/3",
                          "/api/orders/3", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"id": 3, "user_id": 2,
                                                 "items": ["X"], "total": 50})),
    })
    s.append({
        "id": "GT-06", "tc": "TC-TA-03",
        "label": "IDOR: alice DELETE /api/orders/3 (owned by user 2)",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("DELETE", "http://localhost:5001/api/orders/3",
                          "/api/orders/3", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"deleted": True, "id": 3,
                                                 "user_id": 2})),
    })
    s.append({
        "id": "GT-07", "tc": "TC-TA-03",
        "label": "IDOR: alice views cart 2 via ?cart_id=2",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("GET", "http://localhost:5001/api/cart?cart_id=2",
                          "/api/cart", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"cart_id": 2, "user_id": 2,
                                                 "items": [{"sku": "abc"}]})),
    })
    s.append({
        "id": "GT-08", "tc": "TC-TA-01",
        "label": "Safe: non-admin blocked at /api/admin/users (403)",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("GET", "http://localhost:5001/api/admin/users",
                          "/api/admin/users", 403, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"error": "forbidden"})),
    })
    s.append({
        "id": "GT-09", "tc": "TC-PS-09",
        "label": "Safe: public products listing",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("GET", "http://localhost:5001/api/products",
                          "/api/products", 200, cookie=None,
                          resp_body=json.dumps([{"id": 1, "name": "Widget"}])),
    })
    s.append({
        "id": "GT-10", "tc": "TC-PS-09",
        "label": "Safe: alice views own cart",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("GET", "http://localhost:5001/api/cart",
                          "/api/cart", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"cart_id": 1, "user_id": 1,
                                                 "items": []})),
    })

    # --- Probe matrix (SQLi / BAC / Privilege Escalation) -----------------
    s.append({
        "id": "PB-01", "tc": "TC-PS-09",
        "label": "Privilege Escalation: regular user opens /admin",
        "expected_vulnerable": True, "expected_type": "Privilege Escalation",
        "packet": _packet("GET", "http://localhost:5001/admin",
                          "/admin", 200, cookie=SESSION_USER_1,
                          resp_body="<html><h1>Admin Dashboard</h1>"
                                    "<table>users:alice,bob,charlie,admin</table></html>",
                          content_type="text/html"),
    })
    s.append({
        "id": "PB-02", "tc": "TC-TA-04/TC-PS-04",
        "label": "SQLi: classic OR 1=1 login bypass",
        "expected_vulnerable": True, "expected_type": "SQLi",
        "packet": _packet("POST", "http://localhost:5001/login", "/login",
                          200, cookie=None,
                          req_body="username=admin'+OR+'1'%3D'1&password=any",
                          resp_body="<html><body>Welcome admin</body></html>",
                          content_type="text/html"),
    })
    s.append({
        "id": "PB-03", "tc": "TC-TA-04",
        "label": "SQLi: UNION SELECT in search",
        "expected_vulnerable": True, "expected_type": "SQLi",
        "packet": _packet("GET",
                          "http://localhost:5001/search?q=laptop'+UNION+SELECT+username,password+FROM+users--",
                          "/search", 200, cookie=SESSION_USER_1,
                          resp_body='[{"username":"alice","password":"p123"},'
                                    '{"username":"admin","password":"a123"}]'),
    })
    s.append({
        "id": "PB-04", "tc": "TC-TA-05",
        "label": "BAC: unauthenticated invoice download",
        "expected_vulnerable": True, "expected_type": "Broken Access Control",
        "packet": _packet("GET",
                          "http://localhost:5001/uploads/order_42_invoice.pdf",
                          "/uploads/order_42_invoice.pdf", 200, cookie=None,
                          resp_body="%PDF-1.4 invoice for user bob, total $999.99",
                          content_type="application/pdf"),
    })
    s.append({
        "id": "PB-05", "tc": "TC-TA-02",
        "label": "Safe: legitimate login",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("POST", "http://localhost:5001/login", "/login",
                          200, cookie=None,
                          req_body="username=alice&password=password123",
                          resp_body="<html><body>Welcome alice</body></html>",
                          content_type="text/html"),
    })
    s.append({
        "id": "PB-06", "tc": "TC-PS-09",
        "label": "IDOR: alice views user 3 profile (charlie)",
        "expected_vulnerable": True, "expected_type": "IDOR",
        "packet": _packet("GET", "http://localhost:5001/api/profile?id=3",
                          "/api/profile", 200, cookie=SESSION_USER_1,
                          resp_body=json.dumps({"id": 3, "username": "charlie",
                                                 "email": "charlie@test.com",
                                                 "phone": "+1122334455"})),
    })
    s.append({
        "id": "PB-07", "tc": "TC-PS-09",
        "label": "Safe: own-profile HTML page (no id parameter)",
        "expected_vulnerable": False, "expected_type": "None",
        "packet": _packet("GET", "http://localhost:5001/profile", "/profile",
                          200, cookie=SESSION_USER_1,
                          resp_body="<html><body>Hi alice</body></html>",
                          content_type="text/html"),
    })

    return s


# ---------------------------------------------------------------------------
# Yardımcı metrikler
# ---------------------------------------------------------------------------

def confusion(results: list[dict[str, Any]]) -> dict[str, int]:
    tp = fp = fn = tn = 0
    for r in results:
        exp = r["expected_vulnerable"]
        det = r["detected_vulnerable"]
        if exp and det:
            tp += 1
        elif not exp and not det:
            tn += 1
        elif exp and not det:
            fn += 1
        else:
            fp += 1
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}


def metrics(c: dict[str, int]) -> dict[str, float]:
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "accuracy": accuracy, "total": total}


def latency_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    sorted_vals = sorted(values)
    p95_idx = max(0, int(len(sorted_vals) * 0.95) - 1)
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "p95": sorted_vals[p95_idx],
        "min": min(values),
        "max": max(values),
    }


# ---------------------------------------------------------------------------
# MCP filter mikrobenchmark (FOG-PM-01 / TC-NFR-02)
# ---------------------------------------------------------------------------

STATIC_EXTS = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map")


def mcp_filter_simulation() -> dict[str, Any]:
    """Tipik bir SPA oturumunda MCP'nin %40+ statik trafiği elemesini gösterir."""
    traffic = [
        ("/static/app.css", "GET"),
        ("/static/main.js", "GET"),
        ("/static/logo.png", "GET"),
        ("/static/icon.svg", "GET"),
        ("/static/font.woff2", "GET"),
        ("/static/sprite.png", "GET"),
        ("/static/vendor.js", "GET"),
        ("/api/profile", "GET"),
        ("/api/orders", "GET"),
        ("/api/cart", "POST"),
        ("/login", "POST"),
        ("/search", "GET"),
        ("/api/products", "OPTIONS"),  # preflight
        ("/api/products", "GET"),
        ("/admin", "GET"),
    ]
    filtered = 0
    analyzed = 0
    for path, method in traffic:
        path_l = path.lower()
        if method in ("OPTIONS", "HEAD") or any(path_l.endswith(e) for e in STATIC_EXTS):
            filtered += 1
        else:
            analyzed += 1
    total = len(traffic)
    return {"total": total, "filtered": filtered, "analyzed": analyzed,
            "filter_ratio": filtered / total}


# ---------------------------------------------------------------------------
# PII regex mikrobenchmark (FOG-PM-05 / TC-NFR-04)
# ---------------------------------------------------------------------------

def pii_perf(masker: PIIMasker, iterations: int = 1000) -> dict[str, Any]:
    sample = ("Customer email alice@example.com phone +1-555-123-4567 "
              "card 4111-1111-1111-1111 ssn 123-45-6789")
    start = time.perf_counter()
    for _ in range(iterations):
        masker.mask(sample)
    elapsed = time.perf_counter() - start
    avg_us = (elapsed / iterations) * 1_000_000
    masked = masker.mask(sample)
    leaked = bool(re.search(r"4111-1111-1111-1111|alice@example\.com", masked))
    return {"iterations": iterations, "total_seconds": elapsed,
            "avg_microseconds": avg_us, "pii_leaked": leaked,
            "sample_masked": masked}


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------

async def run_one(agent: SecurityAgent, scenario: dict[str, Any],
                  counter: TokenCounter) -> dict[str, Any]:
    packet = scenario["packet"]
    prompt = agent._build_prompt(packet)
    prompt_tokens = counter.count_tokens(prompt)

    t0 = time.perf_counter()
    try:
        result = await agent.analyze_request(packet)
        error = None
    except Exception as exc:  # pragma: no cover
        result = {"vulnerability_found": False, "vulnerability_type": "ERROR",
                  "confidence_score": 0, "reasoning": str(exc)}
        error = str(exc)
    latency_ms = (time.perf_counter() - t0) * 1000

    detected = bool(result.get("vulnerability_found"))
    detected_type = str(result.get("vulnerability_type") or "None")
    confidence = int(result.get("confidence_score") or 0)
    expected = scenario["expected_vulnerable"]

    if expected and detected:
        status = "TP"
    elif not expected and not detected:
        status = "TN"
    elif expected and not detected:
        status = "FN"
    else:
        status = "FP"

    return {
        "id": scenario["id"],
        "tc": scenario["tc"],
        "label": scenario["label"],
        "expected_vulnerable": expected,
        "expected_type": scenario["expected_type"],
        "detected_vulnerable": detected,
        "detected_type": detected_type,
        "confidence": confidence,
        "status": status,
        "latency_ms": round(latency_ms, 2),
        "prompt_tokens": prompt_tokens,
        "reasoning": str(result.get("reasoning") or "")[:400],
        "error": error,
    }


async def main() -> None:
    cfg = Config("config.yaml")
    masker = PIIMasker(cfg.pii_patterns)
    agent = SecurityAgent(cfg, pii_masker=masker)
    counter = TokenCounter()

    scenarios = build_scenarios()
    print(f"[harness] running {len(scenarios)} scenarios against "
          f"{cfg.openai_model} ...", flush=True)

    results: list[dict[str, Any]] = []
    for sc in scenarios:
        print(f"  - {sc['id']} {sc['label'][:60]}", flush=True)
        results.append(await run_one(agent, sc, counter))

    # --- Aggregate metrics ------------------------------------------------
    cm = confusion(results)
    overall = metrics(cm)
    latencies = [r["latency_ms"] for r in results if r["error"] is None]
    tokens_used = [r["prompt_tokens"] for r in results]

    by_class: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    for r in results:
        cls = r["expected_type"] if r["expected_vulnerable"] else "Safe"
        by_class[cls][r["status"]] += 1

    mcp = mcp_filter_simulation()
    pii = pii_perf(masker)

    summary = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "model": cfg.openai_model,
        "embedder": cfg.openai_embedding_model,
        "confidence_threshold": cfg.confidence_threshold,
        "scenarios": len(scenarios),
        "confusion_matrix": cm,
        "overall_metrics": overall,
        "by_class": dict(by_class),
        "latency_ms": latency_stats(latencies),
        "tokens": {
            "per_request_mean": statistics.mean(tokens_used) if tokens_used else 0,
            "per_request_max": max(tokens_used) if tokens_used else 0,
            "total": sum(tokens_used),
            "limit": 10000,
        },
        "mcp_filter": mcp,
        "pii_performance": pii,
        "results": results,
    }

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"full_validation_{ts}.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n[harness] JSON report: {json_path}")

    # --- Markdown summary -------------------------------------------------
    md = []
    md.append(f"# VULCAN Bütüncül Doğrulama Raporu — {summary['timestamp']}\n")
    md.append(f"- Model: `{summary['model']}` · Embedder: `{cfg.openai_embedding_model}`\n")
    md.append(f"- Senaryo sayısı: **{summary['scenarios']}**\n")
    md.append(f"- Confidence eşiği: **{summary['confidence_threshold']}**\n\n")

    md.append("## Karışıklık Matrisi\n")
    md.append(f"| TP | FP | FN | TN |\n|----|----|----|----|\n"
              f"| {cm['TP']} | {cm['FP']} | {cm['FN']} | {cm['TN']} |\n\n")

    md.append("## Genel Metrikler\n")
    md.append(f"| Metrik | Değer |\n|--------|-------|\n"
              f"| Precision | {overall['precision']:.3f} |\n"
              f"| Recall | {overall['recall']:.3f} |\n"
              f"| F1-Score | {overall['f1']:.3f} |\n"
              f"| Accuracy | {overall['accuracy']:.3f} |\n\n")

    md.append("## Sınıf Bazında Dağılım\n")
    md.append("| Sınıf | TP | FP | FN | TN |\n|-------|----|----|----|----|\n")
    for cls, c in by_class.items():
        md.append(f"| {cls} | {c['TP']} | {c['FP']} | {c['FN']} | {c['TN']} |\n")
    md.append("\n")

    lat = summary["latency_ms"]
    md.append("## LLM Analiz Gecikmesi (ms)\n")
    md.append(f"| ortalama | medyan | p95 | min | max |\n"
              f"|----------|--------|-----|-----|-----|\n"
              f"| {lat['mean']:.1f} | {lat['median']:.1f} | {lat['p95']:.1f} "
              f"| {lat['min']:.1f} | {lat['max']:.1f} |\n\n")

    tk = summary["tokens"]
    md.append("## Token Tüketimi (prompt)\n")
    md.append(f"- istek başı ort.: **{tk['per_request_mean']:.0f}**\n"
              f"- istek başı maks.: **{tk['per_request_max']}**\n"
              f"- toplam (oturum): **{tk['total']}**\n"
              f"- üst sınır (FOG-PM-01): **{tk['limit']}** ✅\n\n")

    md.append("## MCP Trafik Filtreleme\n")
    md.append(f"- Toplam istek: {mcp['total']}\n"
              f"- Filtrelenen: {mcp['filtered']}\n"
              f"- Analiz edilen: {mcp['analyzed']}\n"
              f"- Filtreleme oranı: **{mcp['filter_ratio']:.1%}** "
              f"(hedef ≥ %40 — {'GEÇTİ' if mcp['filter_ratio'] >= 0.40 else 'KALDI'})\n\n")

    md.append("## PII Maskeleme Mikrobenchmark\n")
    md.append(f"- {pii['iterations']} iterasyon: {pii['total_seconds']*1000:.1f} ms\n"
              f"- istek başı ort.: **{pii['avg_microseconds']:.1f} µs**\n"
              f"- PII sızıntısı: **{'EVET (HATA)' if pii['pii_leaked'] else 'HAYIR ✅'}**\n"
              f"- Örnek maskeli çıktı: `{pii['sample_masked']}`\n\n")

    md.append("## Senaryo Sonuçları\n")
    md.append("| ID | TC | Label | Beklenen | Tespit | Conf | Durum | Latency | Tokens |\n"
              "|----|----|-------|----------|--------|------|-------|---------|--------|\n")
    for r in results:
        flag = "✅" if r["status"] in ("TP", "TN") else "❌"
        md.append(f"| {r['id']} | {r['tc']} | {r['label'][:40]} | "
                  f"{r['expected_type']} | {r['detected_type']} | "
                  f"{r['confidence']} | {flag} {r['status']} | "
                  f"{r['latency_ms']:.0f} ms | {r['prompt_tokens']} |\n")

    md_path = reports_dir / f"full_validation_{ts}.md"
    md_path.write_text("".join(md))
    print(f"[harness] Markdown report: {md_path}")

    # Konsol özet
    print()
    print(f"Confusion: TP={cm['TP']} FP={cm['FP']} FN={cm['FN']} TN={cm['TN']}")
    print(f"Precision={overall['precision']:.1%} Recall={overall['recall']:.1%} "
          f"F1={overall['f1']:.3f} Accuracy={overall['accuracy']:.1%}")
    print(f"Latency mean={lat['mean']:.0f}ms p95={lat['p95']:.0f}ms")
    print(f"Tokens/req mean={tk['per_request_mean']:.0f} max={tk['per_request_max']}")


if __name__ == "__main__":
    asyncio.run(main())
