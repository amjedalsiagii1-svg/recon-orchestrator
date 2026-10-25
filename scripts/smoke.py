"""Smoke test — run full pipeline against 127.0.0.1 non-interactively."""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


async def main() -> int:
    print("=" * 60)
    print("  SMOKE TEST — full pipeline against 127.0.0.1")
    print("=" * 60)
    failures = 0
    t0 = time.time()

    from core.scope import Scope
    from core.session import Session
    from phases.p1_network_type import detect as p1
    from phases.p2_discovery import discover as p2
    from phases.p3_target_select import select_target as p3
    from phases.p4_port_scan import scan as p4
    from phases.p5_vuln_scan import scan as p5
    from phases.p6_exploit import prepare as p6
    from phases.p7_report import generate as p7

    scope = Scope()
    print(f"[+] Scope: {scope!r}")

    # Fresh DB in a temp location
    db_path = Path("data/smoke_test.db")
    if db_path.exists():
        db_path.unlink()
    sess = await Session.open(db_path)
    sid = await sess.create("smoke")
    print(f"[+] Session: {sid}")

    # ---- P1 ----
    print("\n[1/7] Phase 1 — Network Type Detection...")
    try:
        r1 = await p1(timeout=3.0)
        r1d = r1.to_dict()
        await sess.log_event("p1", "info", f"class={r1.classification.type}", r1d)
        print(f"  OK: type={r1.classification.type} "
              f"confidence={r1.classification.confidence}")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1

    # ---- P2 ----
    print("\n[2/7] Phase 2 — Discovery (127.0.0.1/32)...")
    try:
        r2 = await p2("127.0.0.1/32", scope=scope, gateway="127.0.0.1", timeout=30)
        r2d = r2.to_dict()
        await sess.log_event("p2", "info", f"{len(r2.devices)} devices", r2d)
        print(f"  OK: {len(r2.devices)} devices, method={r2.scan_method}")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1

    # ---- P3 ----
    print("\n[3/7] Phase 3 — Target Selection...")
    try:
        devices_data = r2.to_dict().get("devices", [])
        target = p3("127.0.0.1", devices_data, scope)
        await sess.set_target("127.0.0.1")
        await sess.log_event("p3", "info", "target=127.0.0.1", target.to_dict())
        print(f"  OK: {target.ip} ({target.device_type})")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1

    # ---- P4 ----
    print("\n[4/7] Phase 4 — Port Scan (quick)...")
    try:
        r4 = await p4("127.0.0.1", profile="quick", scope=scope, timeout=180)
        r4d = r4.to_dict()
        await sess.log_event("p4", "info",
                             f"{len(r4.ports)} open ports", r4d)
        print(f"  OK: {len(r4.ports)} ports, "
              f"duration={r4.duration_seconds}s")
        for prt in r4.ports[:5]:
            print(f"    {prt.port}/{prt.protocol} {prt.service} [{prt.risk}]")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1
        r4d = {"ports": []}

    # ---- P5 ----
    print("\n[5/7] Phase 5 — Vulnerability Scan...")
    try:
        ports_data = r4d.get("ports", [])
        r5 = await p5("127.0.0.1", ports_data, scope=scope, run_nuclei=False)
        r5d = r5.to_dict()
        await sess.log_event("p5", "info", f"{len(r5.vulns)} vulns", r5d)
        print(f"  OK: {len(r5.vulns)} vulns, summary={r5.severity_summary()}")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1
        r5d = {"vulns": []}

    # ---- P6 ----
    print("\n[6/7] Phase 6 — Exploit Planning (dry-run)...")
    try:
        vulns_data = r5d.get("vulns", [])
        r6 = await p6("127.0.0.1", vulns_data, scope=scope)
        r6d = r6.to_dict()
        await sess.log_event("p6", "info", f"{len(r6.plans)} plans", r6d)
        assert all(not p.executed for p in r6.plans), "plans must be dry-run"
        print(f"  OK: {len(r6.plans)} plans, all dry-run")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1

    # ---- P7 ----
    print("\n[7/7] Phase 7 — Report Generation...")
    try:
        result = await p7(sess, filename="smoke-test-report.html")
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "unknown"))
        p = Path(result["path"])
        assert p.exists(), f"report not created: {p}"
        assert p.stat().st_size > 1000, f"report too small: {p.stat().st_size}"
        await sess.log_event("p7", "info", "report", result)
        print(f"  OK: {p} ({result['size_bytes']} bytes)")
    except Exception as e:
        print(f"  FAIL: {e}")
        failures += 1

    await sess.close()

    # ---- Summary ----
    elapsed = time.time() - t0
    print("\n" + "=" * 60)
    if failures == 0:
        print(f"  ✓ SMOKE TEST PASSED in {elapsed:.1f}s")
    else:
        print(f"  ✗ SMOKE TEST FAILED ({failures} phase(s) failed) in {elapsed:.1f}s")
    print("=" * 60)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
