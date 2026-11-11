"""Light, stepped load test against a deployed Cloudsneeker stack.

Each virtual user loops: request, then think for --think seconds. Stages run
10, 25, 50 and 100 users for --duration seconds each. Only read-only,
anonymous requests are sent, so no data is created. Keep think time > 0 when
pointing this at production: the stack is a single small VM.

Usage:
    python -I cloudsneeker/qa/load_probe.py --target api-auth \
        --api https://cloudsneeker-api.southindia.cloudapp.azure.com
Targets:
    api-auth    GET /api/v1/providers anonymously (auth middleware + routing, 401)
    api-ready   GET /health/ready (DB + cache round trip; throttled 60/min/IP)
    ui-signin   GET <ui>/sign-in (Vercel server render)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time

import httpx


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100 * len(s) + 0.5)) - 1))
    return s[k]


async def stage(url: str, users: int, duration: float, think: float, ok_codes: set[int]) -> dict:
    lat: list[float] = []
    codes: dict = {}
    errors = 0
    stop = time.monotonic() + duration
    limits = httpx.Limits(max_connections=users, max_keepalive_connections=users)
    async with httpx.AsyncClient(timeout=30, limits=limits, headers={"User-Agent": "cloudsneeker-qa-load/1.0"}) as c:
        async def user():
            nonlocal errors
            while time.monotonic() < stop:
                t0 = time.monotonic()
                try:
                    r = await c.get(url)
                    codes[r.status_code] = codes.get(r.status_code, 0) + 1
                    if r.status_code not in ok_codes:
                        errors += 1
                except Exception as e:  # noqa: BLE001
                    errors += 1
                    k = type(e).__name__
                    codes[k] = codes.get(k, 0) + 1
                lat.append((time.monotonic() - t0) * 1000)
                await asyncio.sleep(think)

        t_start = time.monotonic()
        await asyncio.gather(*(user() for _ in range(users)))
        wall = time.monotonic() - t_start
    n = len(lat)
    return {
        "users": users,
        "requests": n,
        "rps": round(n / wall, 1),
        "avg_ms": round(statistics.fmean(lat), 1) if lat else 0,
        "p50_ms": round(pct(lat, 50), 1),
        "p95_ms": round(pct(lat, 95), 1),
        "p99_ms": round(pct(lat, 99), 1),
        "max_ms": round(max(lat), 1) if lat else 0,
        "error_rate": round(errors / n * 100, 2) if n else 0,
        "codes": codes,
    }


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["api-auth", "api-ready", "ui-signin"], required=True)
    ap.add_argument("--api", default="https://cloudsneeker-api.southindia.cloudapp.azure.com")
    ap.add_argument("--ui", default="https://cloudsneeker.vercel.app")
    ap.add_argument("--stages", default="10,25,50,100")
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--think", type=float, default=0.5)
    ap.add_argument("--out")
    a = ap.parse_args()
    url, ok = {
        "api-auth": (a.api.rstrip("/") + "/api/v1/providers", {401}),
        "api-ready": (a.api.rstrip("/") + "/health/ready", {200}),
        "ui-signin": (a.ui.rstrip("/") + "/sign-in", {200}),
    }[a.target]
    results = []
    for u in [int(x) for x in a.stages.split(",")]:
        res = await stage(url, u, a.duration, a.think, ok)
        res["target"] = a.target
        print(json.dumps(res))
        results.append(res)
        await asyncio.sleep(5)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
