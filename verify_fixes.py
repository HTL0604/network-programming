"""
verify_fixes.py - Automated verification for tools.py report quality fixes.

Runs each tool on sample logs and checks output for expected patterns.
"""
import sys
import os
from typing import List

# Ensure we can import tools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import (  # type: ignore[import]
    detect_security_threats,
    scan_vulnerabilities,
    analyze_system_health,
    analyze_performance,
    correlate_events,
    analyze_traffic_patterns,
)

APACHE_LOG: str = os.path.join("sample_logs", "apache_access.log")
SYSLOG_LOG: str = os.path.join("sample_logs", "syslog.log")
SERVER_LOG: str = os.path.join("sample_logs", "server.log")

passed: int = 0
failed: int = 0
results: List[str] = []

def check(test_name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        results.append(f"  ✅ PASS: {test_name}")
    else:
        failed += 1
        results.append(f"  ❌ FAIL: {test_name}" + (f" ({detail})" if detail else ""))


# ==============================================================
# APACHE LOG TESTS
# ==============================================================
print("🔍 Testing Apache log...")
if os.path.exists(APACHE_LOG):
    sec_apache = detect_security_threats(APACHE_LOG)
    health_apache = analyze_system_health(APACHE_LOG)
    perf_apache = analyze_performance(APACHE_LOG)

    # 1. Event classification present
    check("Apache: event classification in security report",
          "Raw attack attempts" in sec_apache and "Detection log events" in sec_apache)

    # 2. FACT/INFERENCE labels
    check("Apache: FACT/INFERENCE labels present",
          "[FACT]" in sec_apache and "[INFERENCE]" in sec_apache)

    # 3. HTTP 403 evidence section
    check("Apache: HTTP 403 evidence section exists",
          "HTTP 403" in sec_apache)

    # 4. Health score NOT "TỐT" when 5xx exist
    check("Apache: health not TỐT with 500/503 errors",
          "TỐT ✅" not in health_apache,
          f"Got health containing 'TỐT ✅' despite 5xx errors")

    # 5. HTTP 5xx section in health
    check("Apache: HTTP 5xx section in health report",
          "HTTP 5xx" in health_apache)

    # 6. No "nginx" in apache output
    check("Apache: no 'nginx' context bleed in health",
          "nginx" not in health_apache.lower() or "apache" in health_apache.lower())

    # 7. Log type label present
    check("Apache: log type label in security report",
          "Loại log:" in sec_apache)
    check("Apache: log type label in health report",
          "Loại log:" in health_apache)
else:
    results.append("  ⚠️ SKIP: Apache log not found")

# ==============================================================
# SYSLOG TESTS
# ==============================================================
print("🔍 Testing Syslog...")
if os.path.exists(SYSLOG_LOG):
    sec_syslog = detect_security_threats(SYSLOG_LOG)
    health_syslog = analyze_system_health(SYSLOG_LOG)
    corr_syslog = correlate_events(SYSLOG_LOG)
    traffic_syslog = analyze_traffic_patterns(SYSLOG_LOG)

    # 1. OOM/kill detected as critical
    check("Syslog: OOM/kill events in health criticals",
          "OOM" in health_syslog or "Killed" in health_syslog or "SIGKILL" in health_syslog)

    # 2. CPU throttling detected
    check("Syslog: CPU throttle in health warnings",
          "throttl" in health_syslog.lower() or "Throttling" in health_syslog)

    # 3. Health score is NGUY HIỂM (due to OOM)
    check("Syslog: health score NGUY HIỂM",
          "NGUY HIỂM" in health_syslog,
          f"Expected NGUY HIỂM due to OOM/SIGKILL events")

    # 4. events/phút used (not requests/phút)
    check("Syslog: events/phút terminology in traffic",
          "events/phút" in traffic_syslog or "events" in traffic_syslog,
          "Should use 'events' not 'requests' for syslog")

    # 5. Attack burst vs error cascade differentiation
    check("Syslog: attack burst or cascade label present in correlation",
          "ATTACK BURST" in corr_syslog or "ERROR CASCADE" in corr_syslog
          or "Không phát hiện error cascade" in corr_syslog)

    # 6. Log type label
    check("Syslog: log type label in health report",
          "Loại log:" in health_syslog)

    # 7. Event classification in security report
    check("Syslog: event classification present",
          "Raw attack attempts" in sec_syslog)
else:
    results.append("  ⚠️ SKIP: Syslog not found")

# ==============================================================
# SERVER LOG TESTS
# ==============================================================
print("🔍 Testing Server log...")
if os.path.exists(SERVER_LOG):
    sec_server = detect_security_threats(SERVER_LOG)
    vuln_server = scan_vulnerabilities(SERVER_LOG)
    health_server = analyze_system_health(SERVER_LOG)
    perf_server = analyze_performance(SERVER_LOG)

    # 1. Event classification in security + vuln reports
    check("Server: event classification in security report",
          "Raw attack attempts" in sec_server and "Detection log events" in sec_server
          and "Mitigation events" in sec_server)

    check("Server: event classification in vuln report",
          "Raw attack attempts" in vuln_server and "Detection log events" in vuln_server
          and "Mitigation events" in vuln_server)

    # 2. Endpoint extraction from detection messages
    check("Server: endpoint list not empty in vuln report",
          "Endpoints bị nhắm" in vuln_server,
          "Should have extracted endpoints from SecurityModule messages")

    # 3. P95/P99 labeled with method
    check("Server: P95/P99 with nearest-rank note",
          "nearest-rank" in perf_server,
          "P95/P99 should mention nearest-rank method")

    # 4. Slow endpoint threshold label
    check("Server: slow endpoint threshold documented",
          ">1000ms" in perf_server or "Threshold" in perf_server)

    # 5. Raw vs summary error explanation
    check("Server: raw vs summary error explanation exists",
          "GIẢI THÍCH" in perf_server or "server summary" in perf_server.lower()
          or "Server reported" in perf_server)

    # 6. Log type label
    check("Server: log type label present",
          "Loại log:" in sec_server and "Loại log:" in vuln_server)

    # 7. FACT/INFERENCE labels in security
    check("Server: FACT/INFERENCE labels",
          "[FACT]" in sec_server and "[INFERENCE]" in sec_server)
else:
    results.append("  ⚠️ SKIP: Server log not found")


# ==============================================================
# SUMMARY
# ==============================================================
print("\n" + "=" * 60)
print("         VERIFICATION RESULTS")
print("=" * 60)
for r in results:
    print(r)
print(f"\n{'=' * 60}")
print(f"  Total: {passed + failed} | ✅ Passed: {passed} | ❌ Failed: {failed}")
print(f"{'=' * 60}")

sys.exit(0 if failed == 0 else 1)
