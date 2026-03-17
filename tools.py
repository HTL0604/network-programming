"""
tools.py - Custom tools cho hệ thống Multi-Agent phân tích log server.
Tất cả tools được định nghĩa tại đây, không cho phép agents tự định nghĩa.
Hỗ trợ đa định dạng log: Custom, Nginx, Apache, Syslog.
"""

import os
import re
import math
from urllib.parse import unquote_plus
from datetime import datetime
from collections import Counter, defaultdict
from typing import Annotated, Any, Dict

from log_parser_utils import parse_log_to_entries, get_format_display_name


# --- Type-safe factory functions for defaultdict ---

def _new_ip_activity() -> Dict[str, Any]:
    """Factory for scan_vulnerabilities ip_activities defaultdict."""
    return {
        "timestamps": [],
        "attack_types": Counter(),
        "blocked": False,
        "watchlist": False,
        "target_accounts": set(),
        "target_endpoints": set(),
        "log_entries": [],
    }


def _new_ip_data() -> Dict[str, Any]:
    """Factory for analyze_traffic_patterns ip_data defaultdict."""
    return {
        "count": 0,
        "endpoints": Counter(),
        "methods": Counter(),
        "status_codes": Counter(),
        "user_agents": set(),
        "timestamps": [],
        "is_internal": False,
        "is_bot": False,
    }


# ============================================================
# GLOBAL HELPERS
# ============================================================

# Lab hiện tại: coi 192.168.* và 127.* là internal/trusted.
# Nếu môi trường của bạn dùng 10.* hoặc 172.16-31.* là internal, sửa tại đây.
TRUSTED_INTERNAL_PREFIXES = ("192.168.", "127.")


def is_trusted_internal_ip(ip: str) -> bool:
    """Kiểm tra IP có thuộc nhóm internal/trusted trong lab hiện tại hay không."""
    return bool(ip) and ip.startswith(TRUSTED_INTERNAL_PREFIXES)


def extract_all_ips(text: str) -> list[str]:
    """Trích xuất tất cả IPv4 từ chuỗi."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")


def parse_ts(ts: str):
    """Parse timestamp chuẩn YYYY-MM-DD HH:MM:SS, trả None nếu lỗi."""
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def detect_log_type(file_path: str) -> str:
    """
    Tự động nhận diện loại log.

    Supported:
    - apache_access
    - nginx_access
    - syslog
    - system
    - unknown
    """
    filename = os.path.basename(file_path).lower()

    # Ưu tiên filename heuristic trước
    if "nginx" in filename:
        return "nginx_access"
    if "apache" in filename:
        return "apache_access"
    if "syslog" in filename:
        return "syslog"
    if "system" in filename:
        return "system"

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [f.readline() for _ in range(20)]
    except Exception:
        return "unknown"

    sample = "\n".join(lines)

    # Nginx access log: thường có referrer + user-agent ở cuối
    nginx_pattern = (
        r'^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?\s+HTTP/[\d.]+"\s+\d{3}\s+\d+\s+".*?"\s+".*?"$'
    )
    if re.search(nginx_pattern, sample, re.MULTILINE):
        return "nginx_access"

    # Apache access log: dạng common/simple không có referrer/user-agent
    apache_pattern = (
        r'^\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+\[.*?\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+.*?\s+HTTP/[\d.]+"\s+\d{3}\s+\d+$'
    )
    if re.search(apache_pattern, sample, re.MULTILINE):
        return "apache_access"

    # Syslog / system log
    syslog_pattern = r'^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+'
    if re.search(syslog_pattern, sample, re.MULTILINE):
        # nếu filename không giúp phân biệt, mặc định syslog
        return "syslog"

    # Fallback system patterns
    system_patterns = [
        r"kernel:",
        r"systemd\[\d+\]",
        r"sshd\[\d+\]",
        r"cron\[\d+\]",
        r"smartd\[\d+\]",
    ]
    for p in system_patterns:
        if re.search(p, sample):
            return "system"

    return "unknown"

# ============================================================
# TOOL 1: Parse Log File - Phân tích tổng quan file log
# ============================================================

def parse_log_file(
    file_path: Annotated[str, "Đường dẫn tới file log cần phân tích"]
) -> str:
    """
    Đọc và phân tích cấu trúc file log server, trả về thống kê tổng quan.
    Hỗ trợ đa định dạng: Custom App Log, Nginx, Apache, Syslog.  # type: ignore
    Tự động nhận diện format.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    # =========================
    # Detect log type
    # =========================
    log_type = detect_log_type(file_path)

    # Parse log entries
    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    if not entries:
        return f"""
LOG TYPE DETECTED: {log_type}

ERROR: Không thể parse file log. Format không được nhận diện."""

    total_lines = len(entries)
    log_levels = Counter()
    ips = Counter()
    endpoints = Counter()
    services = Counter()
    http_status_codes = Counter()
    methods = Counter()

    timestamps = [entry.timestamp for entry in entries if entry.timestamp]
    timestamps_sorted = sorted(timestamps) if timestamps else []

    for entry in entries:
        log_levels[entry.level] += 1
        services[entry.service] += 1

        if entry.ip:
            ips[entry.ip] += 1
        if entry.method:
            methods[entry.method] += 1
        if entry.endpoint:
            endpoints[entry.endpoint] += 1
        if entry.status_code is not None:
            http_status_codes[str(entry.status_code)] += 1

    time_range = "N/A"
    if timestamps_sorted:
        time_range = f"{timestamps_sorted[0]} → {timestamps_sorted[-1]}"

    result = f"""
===== BÁO CÁO PHÂN TÍCH TỔNG QUAN LOG =====

📄 Tổng số dòng log: {total_lines}
📄 Loại log nhận diện: {log_type}
📂 Định dạng log: {format_name} ({log_format})
⏰ Khoảng thời gian: {time_range}

📊 PHÂN LOẠI THEO LOG LEVEL:
{chr(10).join(f'  - {level}: {count} entries' for level, count in log_levels.most_common())}

🔧 SERVICES XUẤT HIỆN:
{chr(10).join(f'  - {svc}: {count} entries' for svc, count in services.most_common())}

🌐 HTTP METHODS:
{chr(10).join(f'  - {method}: {count} requests' for method, count in methods.most_common()) if methods else '  - N/A (không có HTTP request trong log)'}

📡 HTTP STATUS CODES:
{chr(10).join(f'  - {code}: {count} responses' for code, count in http_status_codes.most_common()) if http_status_codes else '  - N/A'}

🖥️ TOP IP ADDRESSES:
{chr(10).join(f'  - {ip}: {count} requests' for ip, count in ips.most_common(10)) if ips else '  - N/A'}

🔗 TOP ENDPOINTS:
{chr(10).join(f'  - {ep}: {count} hits' for ep, count in endpoints.most_common(10)) if endpoints else '  - N/A'}
"""
    return result.strip()


# ============================================================
# TOOL 2: Extract Error Entries - Lọc các lỗi
# ============================================================

def extract_error_entries(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Lọc và trích xuất tất cả các dòng log có level ERROR hoặc CRITICAL,
    phân loại theo service và mức độ nghiêm trọng.
    Hỗ trợ đa định dạng log.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    errors = []
    criticals = []
    error_by_service = defaultdict(list)

    for entry in entries:
        if entry.level in ("ERROR", "CRITICAL"):
            item = {
                "timestamp": entry.timestamp,
                "level": entry.level,
                "service": entry.service,
                "message": (entry.message or "").strip(),
            }
            error_by_service[entry.service].append(item)
            if entry.level == "CRITICAL":
                criticals.append(item)
            else:
                errors.append(item)

    result = f"""
===== TRÍCH XUẤT LỖI (ERROR/CRITICAL) =====

📂 Định dạng log: {format_name}
🔴 Tổng số CRITICAL: {len(criticals)}
🟠 Tổng số ERROR: {len(errors)}
📊 Tổng cộng: {len(criticals) + len(errors)} lỗi

--- CRITICAL ENTRIES ---
"""
    for entry in criticals:
        result += f"  [{entry['timestamp']}] [{entry['service']}] {entry['message']}\n"

    result += "\n--- ERROR ENTRIES ---\n"
    for entry in errors:
        result += f"  [{entry['timestamp']}] [{entry['service']}] {entry['message']}\n"

    result += "\n--- LỖI PHÂN THEO SERVICE ---\n"
    for service, entries_list in error_by_service.items():
        result += f"  🔧 {service}: {len(entries_list)} lỗi\n"
        for e in entries_list:
            result += f"     - [{e['level']}] {e['message']}\n"

    return result.strip()


# ============================================================
# TOOL 3: Detect Security Threats - Phát hiện lỗ hổng bảo mật
# ============================================================

def detect_security_threats(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích file log để phát hiện mối đe dọa bảo mật dựa trên bằng chứng trực tiếp."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)
    format_name = get_format_display_name(log_format)

    if not entries:
        return "ERROR: Không thể parse file log."

    threats = {
        "sql_injection": [],
        "nosql_injection": [],
        "command_injection": [],
        "ldap_injection": [],
        "xss": [],
        "path_traversal": [],
        "brute_force": [],
        "ddos_flooding": [],
        "unauthorized_access": [],
        "sensitive_data_exposure": [],
    }

    seen = {k: set() for k in threats}
    suspicious_ips = set()
    blocked_ips = set()
    watchlist_ips = set()
    ip_activity = Counter()
    login_failures = defaultdict(list)

    def add_finding(category: str, line_text: str):
        if line_text not in seen[category]:
            seen[category].add(line_text)
            threats[category].append(line_text)

        for ip in extract_all_ips(line_text):
            if not is_trusted_internal_ip(ip):
                suspicious_ips.add(ip)
                ip_activity[ip] += 1

    sql_patterns = [
        r"(?i)\bSQL\s+Injection\b",
        r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        r"(?i)\bSELECT\s+.+\s+FROM\b",
        r"(?i)\bSELECT\s+\*\s+FROM\s+users\b",
        r"(?i)\bUNION\s+SELECT\s+password\s+FROM\s+admin\b",
        r"(?i)\bOR\s+'1'\s*=\s*'1'\b",
        r"(?i)'\s*OR\s*'1'\s*=\s*'1",
        r"(?i)\bOR\s+1\s*=\s*1\b",
        r"(?i)\bDROP\s+TABLE\b",
    ]

    nosql_patterns = [
        r"(?i)\bNoSQL\s+Injection\b",
        r'(?i)\{\s*"\$gt"\s*:',
        r'(?i)\{\s*"\$ne"\s*:',
        r"(?i)\$regex",
        r"(?i)\$where",
    ]

    command_injection_patterns = [
        r"(?i)\bCommand\s+Injection\b",
        r"(?i)\bOS\s+Command\s+Injection\b",
        r"(?i)\|\s*(wget|curl|bash|sh)\b",
        r"(?i);\s*(cat|wget|curl|bash|sh)\b",
        r"(?i)/bin/(bash|sh)\b",
        r"(?i)\bcmd=;cat\s+\S+",
    ]

    ldap_patterns = [
        r"(?i)\bLDAP\s+Injection\b",
        r"(?i)\*\)\(&",
        r"(?i)objectClass=\*",
    ]

    xss_patterns = [
        r"(?i)\bXSS\b",
        r"(?i)<script[\s>]",
        r"(?i)</script>",
        r"(?i)alert\s*\(",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
    ]

    traversal_patterns = [
        r"(?i)\.\./\.\./",
        r"(?i)\.\./etc/passwd",
        r"(?i)\bPath\s+traversal\b",
        r"(?i)\bdirectory\s+traversal\b",
        r"(?i)\bLFI\b",
    ]

    brute_force_patterns = [
        # Generic login failures (application logs)
        r"(?i)failed\s+login",
        r"(?i)login\s+failed",
        r"(?i)invalid\s+credentials",
        r"(?i)authentication\s+failure",

        # Too many login attempts
        r"(?i)too\s+many\s+login\s+attempts",
        r"(?i)maximum\s+authentication\s+attempts\s+exceeded",

        # SSH brute force (syslog)
        r"(?i)Failed\s+password\s+for\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)Invalid\s+user\s+.*\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)authentication\s+failure.*from\s+(\d+\.\d+\.\d+\.\d+)",
        r"(?i)connection\s+closed\s+by\s+(\d+\.\d+\.\d+\.\d+).*preauth",
    ]

    ddos_patterns = [
        r"(?i)\bddos\b",
        r"(?i)\bdos\b",
        r"(?i)syn\s+flood",
        r"(?i)possible\s+syn\s+flooding",
        r"(?i)flood(ing)?",
        r"(?i)rate\s+limit",
        r"(?i)too\s+many\s+requests",
        r"(?i)connection\s+limit\s+exceeded",
        r"(?i)too\s+many\s+connections",
    ]

    unauthorized_patterns = [
        # Access denied / Forbidden
        r"(?i)access\s+denied",
        r"(?i)forbidden",
        r"(?i)403\s+forbidden",

        # Unauthorized access
        r"(?i)unauthorized",
        r"(?i)authentication\s+required",

        # Directory traversal / forced browsing
        r"(?i)\.\./",
        r"(?i)/etc/passwd",
        r"(?i)directory\s+traversal",

        # Sensitive file access
        r"(?i)/\.env",
        r"(?i)/\.git/config",
        r"(?i)/\.ssh/",

        # Forced browsing
        r"(?i)forced\s+browsing",
        r"(?i)access\s+to\s+restricted\s+area",
    ]

    sensitive_data_patterns = [
        r"(?i)\b(password|passwd|secret|api[_-]?key|token|credential)\b\s*[=:]\s*\S+",
        r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        r"(?i)\bdebug\s*=\s*true\b",
        r"(?i)\btraceback\b",
        r"(?i)\bstack\s*trace\b",
    ]

    # =========================================================
    # Vòng quét chính
    # =========================================================
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_line = unquote_plus(line_text)
        lower = decoded_line.lower()

        # Ghi nhận block/watchlist nếu có trong log
        if "added to blocklist" in lower or "ufw block" in lower:
            for ip in extract_all_ips(decoded_line):
                if not is_trusted_internal_ip(ip):
                    blocked_ips.add(ip)

        if "added to watchlist" in lower:
            for ip in extract_all_ips(decoded_line):
                if not is_trusted_internal_ip(ip):
                    watchlist_ips.add(ip)

        checks = [
            ("sql_injection", sql_patterns),
            ("nosql_injection", nosql_patterns),
            ("command_injection", command_injection_patterns),
            ("ldap_injection", ldap_patterns),
            ("xss", xss_patterns),
            ("path_traversal", traversal_patterns),
            ("brute_force", brute_force_patterns),
            ("ddos_flooding", ddos_patterns),
            ("unauthorized_access", unauthorized_patterns),
            ("sensitive_data_exposure", sensitive_data_patterns),
        ]

        for category, patterns in checks:
            if any(re.search(pattern, decoded_line) for pattern in patterns):
                add_finding(category, line_text)

        # Heuristic brute-force cho access log:
        # cùng 1 IP POST vào endpoint login và nhận 401/403 nhiều lần
        decoded_endpoint = unquote_plus(entry.endpoint or "")
        if (
            entry.ip
            and entry.method == "POST"
            and decoded_endpoint in ("/api/login", "/login", "/auth/login")
            and entry.status_code in (401, 403)
        ):
            login_failures[entry.ip].append({
                "timestamp": entry.timestamp,
                "endpoint": decoded_endpoint,
                "status": entry.status_code,
                "raw": line_text,
            })

    # Nếu 1 IP có >= 5 login failures thì coi là brute-force
    for ip, attempts in login_failures.items():
        if len(attempts) >= 5:
            for item in attempts:
                add_finding("brute_force", item["raw"])

    risk_weights = {
        "sql_injection": 10,
        "nosql_injection": 9,
        "command_injection": 10,
        "ldap_injection": 8,
        "xss": 7,
        "path_traversal": 8,
        "brute_force": 6,
        "ddos_flooding": 7,
        "unauthorized_access": 7,
        "sensitive_data_exposure": 9,
    }

    total_threats = sum(len(v) for v in threats.values())
    risk_score = sum(len(threats[k]) * risk_weights[k] for k in risk_weights)

    if risk_score == 0:
        severity = "✅ AN TOÀN - Không phát hiện mối đe dọa rõ ràng"
    elif risk_score <= 20:
        severity = "🟡 THẤP - Có một vài dấu hiệu đáng ngờ"
    elif risk_score <= 50:
        severity = "🟠 TRUNG BÌNH - Có nhiều dấu hiệu cần xử lý"
    elif risk_score <= 100:
        severity = "🔴 CAO - Có nhiều mối đe dọa đáng kể"
    else:
        severity = "🚨 RẤT CAO - Phát hiện nhiều hoạt động tấn công rõ ràng"

    result = f"""
===== BÁO CÁO PHÂN TÍCH BẢO MẬT CHI TIẾT =====

📂 Định dạng log: {format_name}
🛡️ Mức độ nghiêm trọng: {severity}
📊 Risk Score: {risk_score}
📊 Tổng số phát hiện bảo mật: {total_threats}
🚨 Số IP đáng ngờ: {len(suspicious_ips)}
🚫 Số IP bị block rõ ràng từ log: {len(blocked_ips)}
👀 Số IP vào watchlist: {len(watchlist_ips)}

--- 💉 SQL INJECTION ({len(threats['sql_injection'])}) ---
"""
    if threats["sql_injection"]:
        for item in threats["sql_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🗄️ NoSQL INJECTION ({len(threats['nosql_injection'])}) ---\n"
    if threats["nosql_injection"]:
        for item in threats["nosql_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 💻 COMMAND INJECTION ({len(threats['command_injection'])}) ---\n"
    if threats["command_injection"]:
        for item in threats["command_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 📂 LDAP INJECTION ({len(threats['ldap_injection'])}) ---\n"
    if threats["ldap_injection"]:
        for item in threats["ldap_injection"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔓 XSS ({len(threats['xss'])}) ---\n"
    if threats["xss"]:
        for item in threats["xss"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 📁 PATH TRAVERSAL / LFI ({len(threats['path_traversal'])}) ---\n"
    if threats["path_traversal"]:
        for item in threats["path_traversal"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔨 BRUTE FORCE ({len(threats['brute_force'])}) ---\n"
    if threats["brute_force"]:
        for item in threats["brute_force"]:
            result += f"  🟡 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🌊 DDoS / FLOODING ({len(threats['ddos_flooding'])}) ---\n"
    if threats["ddos_flooding"]:
        for item in threats["ddos_flooding"]:
            result += f"  🟠 {item}\n"
        result += "  📌 Lưu ý: Chỉ ghi nhận dấu hiệu flooding từ log; không tự gán IP nguồn nếu log không nêu rõ.\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🚫 UNAUTHORIZED / FORCED BROWSING ({len(threats['unauthorized_access'])}) ---\n"
    if threats["unauthorized_access"]:
        for item in threats["unauthorized_access"]:
            result += f"  🟠 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += f"\n--- 🔐 SENSITIVE DATA EXPOSURE ({len(threats['sensitive_data_exposure'])}) ---\n"
    if threats["sensitive_data_exposure"]:
        for item in threats["sensitive_data_exposure"]:
            result += f"  🔴 {item}\n"
    else:
        result += "  ✅ Không phát hiện\n"

    result += "\n--- 🚨 IP ĐÁNG NGỜ ---\n"
    if suspicious_ips:
        for ip in sorted(suspicious_ips):
            status_parts = []
            if ip in blocked_ips:
                status_parts.append("BLOCKED")
            if ip in watchlist_ips:
                status_parts.append("WATCHLIST")
            status = f" [{' | '.join(status_parts)}]" if status_parts else ""
            result += f"  🔴 {ip}{status} (liên quan {ip_activity[ip]} phát hiện)\n"
    else:
        result += "  ✅ Không có IP đáng ngờ\n"

    return result.strip()


# ============================================================
# TOOL 3b: Scan Vulnerabilities - Quét lỗ hổng bảo mật chuyên sâu
# ============================================================

def scan_vulnerabilities(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Quét chuyên sâu hoạt động tấn công theo timeline và theo IP."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    ip_activities: Dict[str, Dict[str, Any]] = defaultdict(_new_ip_activity)

    attack_timeline = []

    attack_signatures = {
        "SQL_INJECTION": [
            r"(?i)\bSQL\s+Injection\b",
            r"(?i)\bUNION\s+SELECT\b",
            r"(?i)\bSELECT\s+.+\s+FROM\b",
            r"(?i)\bSELECT\s+\*\s+FROM\s+users\b",
            r"(?i)\bUNION\s+SELECT\s+password\s+FROM\s+admin\b",
            r"(?i)\bOR\s+'1'\s*=\s*'1'\b",
            r"(?i)'\s*OR\s*'1'\s*=\s*'1",
            r"(?i)\bOR\s+1\s*=\s*1\b",
        ],
        "XSS": [
            r"(?i)\bXSS\b",
            r"(?i)<script[\s>]",
            r"(?i)</script>",
            r"(?i)alert\s*\(",
        ],
        "COMMAND_INJECTION": [
            r"(?i)\bCommand\s+Injection\b",
            r"(?i)\bOS\s+Command\s+Injection\b",
            r"(?i)\|\s*(wget|curl|bash|sh)\b",
            r"(?i);\s*(cat|wget|curl|bash|sh)\b",
            r"(?i)/bin/(bash|sh)\b",
        ],
        "PATH_TRAVERSAL": [
            r"(?i)\.\./\.\./",
            r"(?i)\.\./etc/passwd",
            r"(?i)\bPath\s+traversal\b",
            r"(?i)\bdirectory\s+traversal\b",
            r"(?i)\bLFI\b",
        ],
        "BRUTE_FORCE": [
            r"(?i)\bFailed\s+login\s+attempt\b",
            r"(?i)\bInvalid\s+credentials\b",
            r"(?i)\bAccount\s+'.+'\s+locked\b",
            r"(?i)\bBrute-?force\s+attack\s+detected\b",
            r"(?i)\bRapid\s+login\s+attempts\s+detected\b",
        ],
        "NOSQL_INJECTION": [
            r"(?i)\bNoSQL\s+Injection\b",
            r'(?i)\{\s*"\$gt"\s*:',
            r'(?i)\{\s*"\$ne"\s*:',
            r"(?i)\$regex",
            r"(?i)\$where",
        ],
        "LDAP_INJECTION": [
            r"(?i)\bLDAP\s+Injection\b",
            r"(?i)\*\)\(&",
        ],
        "DDOS_OR_FLOODING": [
            r"(?i)\bSYN\s+flood(ing)?\b",
            r"(?i)\bflood(ing)?\b",
            r"(?i)\bDDoS\b",
            r"(?i)\btoo\s+many\s+requests\b",
        ],
        "UNAUTHORIZED_ACCESS": [
            r"(?i)\bForced\s+browsing\b",
            r"(?i)/\.env\b",
            r"(?i)/\.git/config\b",
            r"(?i)\bUnauthorized\s+access\b",
            r"(?i)\b403\b.*\bForbidden\b",
        ],
    }

    def mark_ip_state(decoded_text: str):
        lower = decoded_text.lower()
        ips = extract_all_ips(decoded_text)
        for ip in ips:
            if is_trusted_internal_ip(ip):
                continue
            if "added to blocklist" in lower or "ufw block" in lower:
                ip_activities[ip]["blocked"] = True
            if "added to watchlist" in lower:
                ip_activities[ip]["watchlist"] = True

    # =========================================================
    # Heuristic brute-force cho access log:
    # cùng IP POST vào endpoint login và nhận 401/403 >= 5 lần
    # =========================================================
    login_failures = defaultdict(list)

    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_endpoint = unquote_plus(entry.endpoint or "")
        if (
            entry.ip
            and entry.method == "POST"
            and decoded_endpoint in ("/api/login", "/login", "/auth/login")
            and entry.status_code in (401, 403)
        ):
            login_failures[entry.ip].append({
                "timestamp": entry.timestamp,
                "endpoint": decoded_endpoint,
                "status": entry.status_code,
                "raw": line_text,
            })

    confirmed_bruteforce_lines = set()
    for ip, attempts in login_failures.items():
        if len(attempts) >= 5:
            for item in attempts:
                confirmed_bruteforce_lines.add(item["raw"])

    # =========================================================
    # Main scan
    # =========================================================
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message
        if not line_text:
            continue

        decoded_line = unquote_plus(line_text)

        mark_ip_state(decoded_line)

        ips = extract_all_ips(decoded_line)
        if entry.ip and entry.ip not in ips:
            ips.append(entry.ip)

        matched_types = []

        for attack_type, patterns in attack_signatures.items():
            if any(re.search(pattern, decoded_line) for pattern in patterns):
                matched_types.append(attack_type)

        # Heuristic brute-force from access log
        if line_text in confirmed_bruteforce_lines and "BRUTE_FORCE" not in matched_types:
            matched_types.append("BRUTE_FORCE")

        if not matched_types:
            continue

        external_ips = [ip for ip in ips if not is_trusted_internal_ip(ip)]

        for attack_type in matched_types:
            attack_timeline.append({
                "timestamp": entry.timestamp,
                "type": attack_type,
                "level": entry.level,
                "service": entry.service,
                "message": (entry.message or "").strip(),
                "ips": external_ips,
            })

            for ip in external_ips:
                ip_activities[ip]["timestamps"].append(entry.timestamp)  # type: ignore
                ip_activities[ip]["attack_types"][attack_type] += 1  # type: ignore
                ip_activities[ip]["log_entries"].append(  # type: ignore
                    f"[{entry.timestamp}] {attack_type}: {(entry.message or '')[:120]}"
                )

                if entry.endpoint:
                    ip_activities[ip]["target_endpoints"].add(unquote_plus(entry.endpoint))  # type: ignore

                user_match = re.search(r"(?i)(user|account)\s*['\"]?([\w@.-]+)", decoded_line)
                if user_match:
                    ip_activities[ip]["target_accounts"].add(user_match.group(2))  # type: ignore

    def assess_ip_risk(activity_data):
        score = 0
        score += activity_data["attack_types"].get("SQL_INJECTION", 0) * 10
        score += activity_data["attack_types"].get("COMMAND_INJECTION", 0) * 10
        score += activity_data["attack_types"].get("NOSQL_INJECTION", 0) * 9
        score += activity_data["attack_types"].get("LDAP_INJECTION", 0) * 8
        score += activity_data["attack_types"].get("XSS", 0) * 7
        score += activity_data["attack_types"].get("PATH_TRAVERSAL", 0) * 8
        score += activity_data["attack_types"].get("BRUTE_FORCE", 0) * 6
        score += activity_data["attack_types"].get("DDOS_OR_FLOODING", 0) * 7
        score += activity_data["attack_types"].get("UNAUTHORIZED_ACCESS", 0) * 7

        if score >= 40:
            return "RẤT CAO 🚨", score
        if score >= 25:
            return "CAO 🔴", score
        if score >= 12:
            return "TRUNG BÌNH 🟠", score
        return "THẤP 🟡", score

    sorted_ips = sorted(
        ip_activities.items(),
        key=lambda x: assess_ip_risk(x[1])[1],
        reverse=True,
    )

    result = f"""
===== BÁO CÁO QUÉT LỖ HỔNG BẢO MẬT CHUYÊN SÂU =====

📊 Tổng số sự kiện tấn công/bất thường: {len(attack_timeline)}
🚨 Số IP đáng ngờ: {len(ip_activities)}
⏰ Timeline: {attack_timeline[0]['timestamp'] if attack_timeline else 'N/A'} → {attack_timeline[-1]['timestamp'] if attack_timeline else 'N/A'}

{'='*55}
          TIMELINE CÁC SỰ KIỆN BẢO MẬT
{'='*55}
"""
    if attack_timeline:
        for event in attack_timeline:
            result += f"  - [{event['timestamp']}] {event['type']:18s} | {event['message'][:100]}\n"
    else:
        result += "  ✅ Không phát hiện sự kiện bảo mật rõ ràng\n"

    result += f"\n{'='*55}\n"
    result += f"          PHÂN TÍCH THEO IP\n"
    result += f"{'='*55}\n"

    if not sorted_ips:  # type: ignore
        result += "  ✅ Không có IP đáng ngờ để phân tích\n"
    else:
        for ip, data in sorted_ips:
            risk_label, risk_score = assess_ip_risk(data)
            state_parts = []
            if data["blocked"]:
                state_parts.append("BLOCKED")
            if data["watchlist"]:
                state_parts.append("WATCHLIST")
            state = " | ".join(state_parts) if state_parts else "NO_EXPLICIT_ACTION"

            distinct_types = len(data["attack_types"])
            multi_vector_note = ""
            if distinct_types >= 3:
                multi_vector_note = "⚠️ Dấu hiệu multi-vector behavior (nhiều loại tấn công khác nhau)."

            result += f"""
  ╔══════════════════════════════════════════════╗
  ║ IP: {ip}
  ║ Mức nguy hiểm: {risk_label} (Score: {risk_score})
  ║ Trạng thái từ log: {state}
  ╚══════════════════════════════════════════════╝
    📊 Tổng sự kiện liên quan: {sum(data['attack_types'].values())}
    🔫 Loại tấn công:
"""
            for attack_type, count in data["attack_types"].most_common():
                result += f"       - {attack_type}: {count} lần\n"

            if data["target_accounts"]:
                result += f"    🎯 Accounts bị nhắm: {', '.join(sorted(data['target_accounts']))}\n"
            if data["target_endpoints"]:
                result += f"    🔗 Endpoints bị nhắm: {', '.join(sorted(list(data['target_endpoints']))[:6])}\n"  # type: ignore
            if multi_vector_note:
                result += f"    {multi_vector_note}\n"

            result += "    📜 Bằng chứng:\n"
            for item in data["log_entries"][:5]:
                result += f"       {item}\n"
            if len(data["log_entries"]) > 5:
                result += f"       ... và {len(data['log_entries']) - 5} sự kiện khác\n"

    result += f"\n{'='*55}\n"
    result += f"          KHUYẾN NGHỊ\n"
    result += f"{'='*55}\n"

    all_attack_types = Counter()
    for data in ip_activities.values():
        all_attack_types.update(data["attack_types"])

    recommendations = {
        "SQL_INJECTION": "Sử dụng prepared statements và kiểm soát input query parameters.",
        "XSS": "Encode output và triển khai Content-Security-Policy.",
        "COMMAND_INJECTION": "Không truyền user input trực tiếp vào shell/system commands.",
        "PATH_TRAVERSAL": "Canonicalize path và chỉ cho phép whitelist path hợp lệ.",
        "BRUTE_FORCE": "Rate limit login, account lockout, MFA/CAPTCHA.",
        "NOSQL_INJECTION": "Validate input và tránh build query NoSQL trực tiếp từ user input.",
        "LDAP_INJECTION": "Escape LDAP special characters và validate đầu vào.",
        "DDOS_OR_FLOODING": "Bật rate limit, reverse proxy/WAF, và theo dõi lưu lượng bất thường.",
        "UNAUTHORIZED_ACCESS": "Hạn chế forced browsing bằng access control và ẩn tài nguyên nhạy cảm.",
    }

    if not all_attack_types:
        result += "  ✅ Không có khuyến nghị bảo mật khẩn cấp từ log hiện tại\n"
    else:
        for attack_type, count in all_attack_types.most_common():
            if attack_type in recommendations:
                result += f"  - {attack_type} ({count} sự kiện): {recommendations[attack_type]}\n"  # type: ignore

    urgent_unblocked = [
        ip for ip, data in ip_activities.items()
        if not data["blocked"] and assess_ip_risk(data)[1] >= 25
    ]
    if urgent_unblocked:
        result += "\n  🚨 IP nguy cơ cao chưa thấy bị block rõ ràng trong log:\n"
        for ip in urgent_unblocked:
            result += f"    - {ip}\n"

    return result.strip()


# ============================================================
# TOOL 4: Analyze System Health - Phân tích sức khỏe hệ thống
# ============================================================

def analyze_system_health(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích sức khỏe hệ thống từ log."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    cpu_readings = []
    memory_readings = []
    disk_readings = []
    health_warnings = []
    health_criticals = []
    service_issues = []
    system_events = []

    cpu_pattern = re.compile(r"CPU\s+Usage:\s*(\d+)%")
    mem_pattern = re.compile(r"Memory(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)
    disk_pattern = re.compile(r"Disk(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)

    for entry in entries:
        message = entry.message or ""

        cpu_match = cpu_pattern.search(message)
        if cpu_match:
            cpu_readings.append({"timestamp": entry.timestamp, "value": int(cpu_match.group(1))})

        mem_match = mem_pattern.search(message)
        if mem_match:
            memory_readings.append({"timestamp": entry.timestamp, "value": int(mem_match.group(1))})

        disk_match = disk_pattern.search(message)
        if disk_match:
            disk_readings.append({"timestamp": entry.timestamp, "value": int(disk_match.group(1))})

        if entry.service in ("SystemMonitor", "kernel", "systemd"):
            if entry.level == "CRITICAL":
                health_criticals.append(f"[{entry.timestamp}] {message}")
            elif entry.level in ("WARNING", "ERROR"):
                health_warnings.append(f"[{entry.timestamp}] {message}")
            elif entry.level == "INFO" and any(
                kw in message.lower()
                for kw in ["cleanup", "restart", "summary", "started", "stopped", "killed", "freed"]
            ):
                system_events.append(f"[{entry.timestamp}] {message}")

        if entry.level in ("ERROR", "CRITICAL") and entry.service not in ("SystemMonitor", "kernel"):
            if any(
                kw in message.lower()
                for kw in ["fail", "crash", "timeout", "outofmemory", "exhausted", "killed", "exited", "unavailable"]
            ):
                service_issues.append(f"[{entry.timestamp}] [{entry.service}] {message}")

    def calc_stats(readings):
        if not readings:
            return {"min": "N/A", "max": "N/A", "avg": "N/A"}
        values = [r["value"] for r in readings]
        return {
            "min": min(values),
            "max": max(values),
            "avg": round(sum(values) / len(values), 1),
        }

    cpu_stats = calc_stats(cpu_readings)
    mem_stats = calc_stats(memory_readings)
    disk_stats = calc_stats(disk_readings)

    health_score = "TỐT"
    if health_criticals or (isinstance(cpu_stats["max"], int) and cpu_stats["max"] > 90):
        health_score = "NGUY HIỂM 🔴"
    elif health_warnings or (isinstance(mem_stats["max"], int) and mem_stats["max"] > 85):
        health_score = "CẦN CHÚ Ý ⚠️"

    result = f"""
===== BÁO CÁO SỨC KHỎE HỆ THỐNG =====

🏥 Đánh giá tổng thể: {health_score}

--- 🖥️ CPU USAGE ---
  Min: {cpu_stats['min']}%  |  Max: {cpu_stats['max']}%  |  Trung bình: {cpu_stats['avg']}%
  Số lần đo: {len(cpu_readings)}
"""
    for r in cpu_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] > 70 else "✅"
        result += f"  {status} [{r['timestamp']}] CPU: {r['value']}%\n"

    result += f"""
--- 💾 MEMORY USAGE ---
  Min: {mem_stats['min']}%  |  Max: {mem_stats['max']}%  |  Trung bình: {mem_stats['avg']}%
  Số lần đo: {len(memory_readings)}
"""
    for r in memory_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] > 70 else "✅"
        result += f"  {status} [{r['timestamp']}] Memory: {r['value']}%\n"

    result += f"""
--- 💿 DISK USAGE ---
  Min: {disk_stats['min']}%  |  Max: {disk_stats['max']}%  |  Trung bình: {disk_stats['avg']}%
  Số lần đo: {len(disk_readings)}
"""
    for r in disk_readings:
        status = "🔴" if r["value"] > 90 else "⚠️" if r["value"] >= 80 else "✅"
        result += f"  {status} [{r['timestamp']}] Disk: {r['value']}%\n"

    result += f"\n--- ⚠️ HEALTH WARNINGS ({len(health_warnings)}) ---\n"
    for w in health_warnings:
        result += f"  {w}\n"

    result += f"\n--- 🔴 HEALTH CRITICALS ({len(health_criticals)}) ---\n"
    for c in health_criticals:
        result += f"  {c}\n"

    result += f"\n--- 🔧 SERVICE ISSUES ({len(service_issues)}) ---\n"
    for s in service_issues:
        result += f"  {s}\n"

    result += f"\n--- 📋 SYSTEM EVENTS ---\n"
    for e in system_events:
        result += f"  {e}\n"

    return result.strip()


# ============================================================
# TOOL 5: Analyze Performance - Phân tích hiệu suất
# ============================================================

def analyze_performance(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích hiệu suất hệ thống từ log."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    http_entries = [e for e in entries if e.status_code is not None]

    server_reported_total_requests = None
    server_reported_avg_response = None

    response_times = []
    slow_requests = []
    error_requests = []
    requests_per_minute = Counter()
    status_codes = Counter()
    endpoint_performance = defaultdict(list)

    for entry in http_entries:
        status_code = str(entry.status_code)
        method = entry.method or "UNKNOWN"
        endpoint = entry.endpoint or "/"
        ip = entry.ip or "unknown"
        timestamp = entry.timestamp

        status_codes[status_code] += 1

        if timestamp:
            minute_key = timestamp[:16]
            requests_per_minute[minute_key] += 1

        if entry.response_time is not None:
            resp_time = entry.response_time
            response_times.append(resp_time)
            endpoint_performance[endpoint].append(resp_time)

            if resp_time > 1000:
                slow_requests.append({
                    "timestamp": timestamp,
                    "method": method,
                    "endpoint": endpoint,
                    "response_time": resp_time,
                    "ip": ip,
                })

        if status_code.startswith(("4", "5")):
            error_requests.append({
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status": status_code,
                "response_time": entry.response_time or 0,
                "ip": ip,
            })

    # đọc server summary metrics từ log
    for entry in entries:
        message = entry.message or ""

        m_total = re.search(r"Server status:\s*(\d+)\s+requests processed", message, re.IGNORECASE)
        if m_total:
            server_reported_total_requests = int(m_total.group(1))

        m_avg = re.search(r"Average response time:\s*(\d+)ms", message, re.IGNORECASE)
        if m_avg:
            server_reported_avg_response = int(m_avg.group(1))

    if response_times:
        avg_resp = round(sum(response_times) / len(response_times), 1)
        min_resp = min(response_times)
        max_resp = max(response_times)

        sorted_times = sorted(response_times)
        p95_resp = sorted_times[int(len(sorted_times) * 0.95) - 1]
        p99_resp = sorted_times[int(len(sorted_times) * 0.99) - 1]

    else:
        avg_resp = min_resp = max_resp = p95_resp = p99_resp = "N/A"

    total_requests = len(http_entries)
    total_errors = len(error_requests)

    error_rate = round(total_errors / total_requests * 100, 1) if total_requests > 0 else 0.0

    peak_minute = requests_per_minute.most_common(1)[0] if requests_per_minute else ("N/A", 0)

    endpoint_avg = {}
    for ep, times in endpoint_performance.items():
        if times:
            endpoint_avg[ep] = round(sum(times) / len(times), 1)

    slowest_endpoints = sorted(endpoint_avg.items(), key=lambda x: x[1], reverse=True)[:5]  # type: ignore

    if avg_resp != "N/A":
        if avg_resp < 200:
            perf_grade = "✅ XUẤT SẮC"
        elif avg_resp < 500:
            perf_grade = "👍 TỐT"
        elif avg_resp < 1000:
            perf_grade = "⚠️ CẦN CẢI THIỆN"
        else:
            perf_grade = "🔴 KÉM"
    else:
        perf_grade = "N/A"

    result = f"""
===== BÁO CÁO PHÂN TÍCH HIỆU SUẤT =====

📈 Đánh giá tổng thể: {perf_grade}

--- ⏱️ RESPONSE TIME ---
  Tổng HTTP requests: {total_requests}
  Trung bình: {avg_resp}ms
  Min: {min_resp}ms | Max: {max_resp}ms
  P95: {p95_resp}ms | P99: {p99_resp}ms

--- 📊 THROUGHPUT ---  # type: ignore
  Peak: {peak_minute[1]} requests/phút lúc {peak_minute[0]}
  Requests theo phút:
"""

    for minute, count in sorted(requests_per_minute.items()):
        bar = "█" * min(count, 40)
        result += f"    {minute}: {count} reqs {bar}\n"  # type: ignore

    result += "\n--- 🧾 SERVER SUMMARY METRICS (nếu có trong log) ---\n"
    result += f"  Server reported total requests: {server_reported_total_requests if server_reported_total_requests is not None else 'N/A'}\n"
    result += f"  Server reported average response time: {str(server_reported_avg_response) + 'ms' if server_reported_avg_response is not None else 'N/A'}\n"
    result += "  Ghi chú: Các số liệu này có thể khác với metrics tính từ HTTP entries quan sát trực tiếp.\n"  # type: ignore

    result += f"""  # type: ignore
--- ❌ ERROR RATE ---
  Tổng lỗi: {total_errors}/{total_requests} ({error_rate}%)  # type: ignore
  HTTP Status distribution:
"""

    for code, count in status_codes.most_common():
        indicator = "✅" if code.startswith("2") else "⚠️" if code.startswith("3") else "🟠" if code.startswith("4") else "🔴"
        result += f"    {indicator} {code}: {count}\n"

    result += f"\n--- 🐌 SLOW REQUESTS (>1000ms): {len(slow_requests)} ---\n"

    for req in slow_requests:
        result += f"  🔴 [{req['timestamp']}] {req['method']} {req['endpoint']} - {req['response_time']}ms (IP: {req['ip']})\n"

    result += f"\n--- 📉 SLOWEST ENDPOINTS (avg response time) ---\n"

    for ep, avg_time in slowest_endpoints:
        indicator = "🔴" if avg_time > 1000 else "⚠️" if avg_time > 500 else "✅"
        result += f"  {indicator} {ep}: {avg_time}ms\n"

    result += "\n--- 🚨 ERROR REQUESTS ---\n"

    for req in error_requests:
        result += f"  [{req['timestamp']}] {req['method']} {req['endpoint']} → {req['status']} ({req['response_time']}ms, IP: {req['ip']})\n"

    return result.strip()


# ============================================================
# TOOL 6: Correlate Events - Phân tích tương quan sự kiện
# ============================================================

def correlate_events(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích tương quan thời gian giữa sự kiện.
    Lưu ý: tương quan KHÔNG đồng nghĩa với quan hệ nhân quả.
    """

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:
        return "ERROR: Không thể parse file log."

    error_entries = [e for e in entries if e.level in ("ERROR", "CRITICAL")]
    cascades = []
    current_cascade = []

    for entry in error_entries:
        curr_ts = parse_ts(entry.timestamp)
        if curr_ts is None:
            continue

        if not current_cascade:
            current_cascade = [entry]
            continue

        prev_ts = parse_ts(current_cascade[-1].timestamp)
        if prev_ts is None:
            current_cascade = [entry]
            continue

        diff_seconds = abs((curr_ts - prev_ts).total_seconds())

        if diff_seconds <= 30:
            current_cascade.append(entry)
        else:
            if len(current_cascade) >= 2:
                cascades.append(list(current_cascade))
            current_cascade = [entry]

    if len(current_cascade) >= 2:
        cascades.append(list(current_cascade))

    resource_events = []
    cpu_pattern = re.compile(r"CPU\s+Usage:\s*(\d+)%")
    mem_pattern = re.compile(r"Memory(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)
    disk_pattern = re.compile(r"Disk(?:\s+usage)?:\s*(\d+)%", re.IGNORECASE)

    for entry in entries:
        message = entry.message or ""

        cpu_match = cpu_pattern.search(message)
        mem_match = mem_pattern.search(message)
        disk_match = disk_pattern.search(message)

        if cpu_match:
            value = int(cpu_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "CPU",
                    "value": value,
                    "entry": entry,
                })

        if mem_match:
            value = int(mem_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "Memory",
                    "value": value,
                    "entry": entry,
                })

        if disk_match:
            value = int(disk_match.group(1))
            if value >= 80:
                resource_events.append({
                    "timestamp": entry.timestamp,
                    "type": "Disk",
                    "value": value,
                    "entry": entry,
                })

        if "connection pool exhausted" in message.lower():
            resource_events.append({
                "timestamp": entry.timestamp,
                "type": "DB_POOL",
                "value": 100,
                "entry": entry,
            })

        if "outofmemoryerror" in message.lower():
            resource_events.append({
                "timestamp": entry.timestamp,
                "type": "OOM",
                "value": 100,
                "entry": entry,
            })

    resource_correlations = []
    for res_event in resource_events:
        res_ts = parse_ts(res_event["timestamp"])
        if res_ts is None:
            continue

        nearest_error = None
        nearest_delay = None

        for err in error_entries:
            err_ts = parse_ts(err.timestamp)
            if err_ts is None:
                continue

            diff = (err_ts - res_ts).total_seconds()
            if 0 < diff <= 120:
                if nearest_delay is None or diff < nearest_delay:
                    nearest_delay = diff
                    nearest_error = err

        if nearest_error:
            resource_correlations.append({
                "resource": f"{res_event['type']} event at {res_event['timestamp']} ({(res_event['entry'].message or '')[:80]})",
                "error": f"[{nearest_error.timestamp}] [{nearest_error.service}] {(nearest_error.message or '')[:100]}",
                "delay_seconds": int(nearest_delay),
            })

    root_causes = Counter()
    service_errors = defaultdict(list)
    for entry in error_entries:
        service_errors[entry.service].append(entry)

    for cascade in cascades:
        root_service = cascade[0].service
        root_causes[root_service] += 1

    attack_patterns = [  # type: ignore
        r"(?i)\bSQL\s+Injection\b",
        r"(?i)\bXSS\b",
        r"(?i)\bPath\s+traversal\b",
        r"(?i)\bBrute-?force\s+attack\s+detected\b",
        r"(?i)\bRapid\s+login\s+attempts\s+detected\b",
        r"(?i)\bNoSQL\s+Injection\b",
        r"(?i)\bLDAP\s+Injection\b",
        r"(?i)\bCommand\s+Injection\b",
        r"(?i)\bForced\s+browsing\b",
    ]

    attack_events = []
    for entry in entries:
        line_text = entry.raw_line if entry.raw_line else entry.message  # type: ignore
        if any(re.search(p, line_text or "") for p in attack_patterns):
            attack_events.append(entry)

    candidate_impacts = [
        e for e in entries
        if (  # type: ignore
            e.level in ("ERROR", "CRITICAL") and e.service not in ("SecurityModule", "AuthService")  # type: ignore
        ) or (  # type: ignore
            e.service == "SystemMonitor"
            and e.level in ("WARNING", "CRITICAL")
            and any(k in (e.message or "").lower() for k in [
                "cpu usage exceeded",
                "memory usage exceeded",
                "disk i/o latency",
            ])
        )
    ]

    attack_impact = []
    for atk in attack_events:
        atk_ts = parse_ts(atk.timestamp)
        if atk_ts is None:
            continue

        nearest_impact = None
        nearest_delay = None
        for imp in candidate_impacts:
            imp_ts = parse_ts(imp.timestamp)
            if imp_ts is None:
                continue

            diff = (imp_ts - atk_ts).total_seconds()
            if 0 < diff <= 180:
                if nearest_delay is None or diff < nearest_delay:
                    nearest_delay = diff
                    nearest_impact = imp

        if nearest_impact:
            attack_impact.append({
                "attack": f"[{atk.timestamp}] [{atk.service}] {(atk.message or '')[:90]}",
                "impact": f"[{nearest_impact.timestamp}] [{nearest_impact.service}] {(nearest_impact.message or '')[:90]}",
                "delay_seconds": int(nearest_delay),
            })

    result = f"""
===== BÁO CÁO PHÂN TÍCH TƯƠNG QUAN SỰ KIỆN =====

📊 Tổng log entries: {len(entries)}
🔴 Tổng ERROR/CRITICAL: {len(error_entries)}
🔗 Error cascades phát hiện: {len(cascades)}
📈 Resource → nearest error correlations: {len(resource_correlations)}
⚔️ Attack → nearest impact correlations: {len(attack_impact)}

⚠️ LƯU Ý:
Các kết quả dưới đây là TƯƠNG QUAN THỜI GIAN.
Chúng KHÔNG tự động chứng minh quan hệ nhân quả trực tiếp.

{'='*55}
          ERROR CASCADING ANALYSIS
{'='*55}
"""
    if cascades:
        for i, cascade in enumerate(cascades, 1):
            result += f"\n  🔗 Cascade #{i} ({len(cascade)} events, first error service: {cascade[0].service}):\n"
            for entry in cascade:
                result += f"    → [{entry.timestamp}] [{entry.service}] {(entry.message or '')[:90]}\n"
            result += f"    💡 Earliest event in cascade: {cascade[0].service} - {(cascade[0].message or '')[:100]}\n"
    else:  # type: ignore
        result += "  ✅ Không phát hiện error cascade rõ ràng\n"

    result += f"""
{'='*55}
          RESOURCE → ERROR (TEMPORAL)
{'='*55}
"""  # type: ignore
    if resource_correlations:  # type: ignore
        for corr in resource_correlations:
            result += f"  ⚠️ {corr['resource']}\n"
            result += f"    → Error gần nhất sau {corr['delay_seconds']}s: {corr['error']}\n\n"
    else:
        result += "  ✅ Không phát hiện tương quan thời gian rõ ràng giữa resource event và error\n"

    result += f"""
{'='*55}
          ROOT CAUSE HINTS
{'='*55}
"""
    if root_causes:
        for service, count in root_causes.most_common():
            result += f"  🔍 {service}: xuất hiện đầu tiên trong {count} cascade(s)\n"
        result += f"\n  💡 Service nên ưu tiên kiểm tra: {root_causes.most_common(1)[0][0]}\n"
    else:
        result += "  ✅ Không có gợi ý root cause rõ ràng từ cascade\n"

    result += f"""
{'='*55}
          SERVICE ERROR MAP
{'='*55}
"""
    for service, errs in sorted(service_errors.items(), key=lambda x: len(x[1]), reverse=True):
        result += f"  🔧 {service}: {len(errs)} lỗi\n"
        for e in errs[:3]:
            result += f"     - [{e.timestamp}] {(e.message or '')[:80]}\n"
        if len(errs) > 3:
            result += f"     ... và {len(errs) - 3} lỗi khác\n"

    result += f"""
{'='*55}
          ATTACK → IMPACT (TEMPORAL ONLY)
{'='*55}
"""
    if attack_impact:
        for imp in attack_impact:
            result += f"  ⚔️ Attack event: {imp['attack']}\n"
            result += f"    → Impact gần nhất sau {imp['delay_seconds']}s: {imp['impact']}\n\n"
    else:
        result += "  ✅ Không phát hiện tương quan thời gian rõ ràng giữa attack event và impact\n"

    return result.strip()


# ============================================================
# TOOL 7: Analyze Traffic Patterns - Phân tích traffic
# ============================================================

def analyze_traffic_patterns(
    file_path: Annotated[str, "Đường dẫn tới file log"]
) -> str:
    """Phân tích traffic patterns."""

    if not os.path.exists(file_path):
        return f"ERROR: File '{file_path}' không tồn tại."

    entries, log_format = parse_log_to_entries(file_path)

    if not entries:  # type: ignore
        return "ERROR: Không thể parse file log."

    ip_data: Dict[str, Dict[str, Any]] = defaultdict(_new_ip_data)

    user_agent_pattern = re.compile(r'ua="([^"]*)"')

    bot_signatures = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
        "wfuzz", "hydra", "curl/", "wget/", "python-requests/",
        "scrapy", "bot", "crawler", "spider", "kube-probe",
    ]

    total_requests = 0

    for entry in entries:
        if not entry.ip:
            continue

        ip = entry.ip
        total_requests += 1
        ip_data[ip]["count"] += 1
        ip_data[ip]["timestamps"].append(entry.timestamp)

        if entry.endpoint:
            ip_data[ip]["endpoints"][entry.endpoint] += 1
        if entry.method:
            ip_data[ip]["methods"][entry.method] += 1
        if entry.status_code is not None:
            ip_data[ip]["status_codes"][str(entry.status_code)] += 1

        if is_trusted_internal_ip(ip):
            ip_data[ip]["is_internal"] = True

        ua_match = user_agent_pattern.search(entry.raw_line or "")
        if ua_match:
            ua = ua_match.group(1)
            ip_data[ip]["user_agents"].add(ua)
            if any(bot in ua.lower() for bot in bot_signatures):
                ip_data[ip]["is_bot"] = True

    internal_ips = {ip: d for ip, d in ip_data.items() if d["is_internal"]}
    external_ips = {ip: d for ip, d in ip_data.items() if not d["is_internal"]}
    bot_ips = {ip: d for ip, d in ip_data.items() if d["is_bot"]}

    suspicious_ips = {}
    for ip, data in external_ips.items():
        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        if data["count"] > 0 and error_count > 0 and (error_count / data["count"]) > 0.5:
            suspicious_ips[ip] = data

    requests_per_minute = Counter()
    for entry in entries:
        if entry.ip and entry.timestamp:
            minute_key = entry.timestamp[:16]
            requests_per_minute[minute_key] += 1

    peak_minute = requests_per_minute.most_common(1)[0] if requests_per_minute else ("N/A", 0)
    avg_rpm = round(sum(requests_per_minute.values()) / max(len(requests_per_minute), 1), 1)

    endpoint_hits = Counter()
    for _, data in ip_data.items():
        endpoint_hits.update(data["endpoints"])

    unique_visitors = len(ip_data)
    legitimate_visitors = len(internal_ips) + len({
        ip: d for ip, d in external_ips.items() if ip not in suspicious_ips and ip not in bot_ips
    })

    result = f"""
===== BÁO CÁO PHÂN TÍCH TRAFFIC PATTERNS =====

📊 Tổng requests có IP: {total_requests}
👥 Unique IPs: {unique_visitors}
🏠 Internal IPs: {len(internal_ips)}
🌍 External IPs: {len(external_ips)}  # type: ignore
🤖 Bot IPs: {len(bot_ips)}
⚠️ Suspicious IPs: {len(suspicious_ips)}
👤 Estimated legitimate visitors: {legitimate_visitors}

{'='*55}
          TRAFFIC TIMELINE
{'='*55}
  📈 Average: {avg_rpm} requests/phút
  🔝 Peak: {peak_minute[1]} requests/phút lúc {peak_minute[0]}
"""
    for minute, count in sorted(requests_per_minute.items()):
        bar = "█" * min(count, 40)
        result += f"    {minute}: {count:3d} reqs {bar}\n"

    result += f"""
{'='*55}
          IP CLASSIFICATION
{'='*55}

  🏠 INTERNAL TRAFFIC (trusted):
"""
    for ip, data in sorted(internal_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        top_ep = data["endpoints"].most_common(1)[0][0] if data["endpoints"] else "N/A"
        result += f"    ✅ {ip:18s} | {data['count']:4d} reqs | Top: {top_ep}\n"

    result += f"\n  🌍 EXTERNAL TRAFFIC:\n"
    for ip, data in sorted(external_ips.items(), key=lambda x: x[1]["count"], reverse=True):
        if ip in suspicious_ips:
            icon = "🔴"
            label = "SUSPICIOUS"
        elif ip in bot_ips:
            icon = "🤖"
            label = "BOT"
        else:
            icon = "🟢"
            label = "OK"

        error_count = sum(v for k, v in data["status_codes"].items() if k.startswith(("4", "5")))
        result += f"    {icon} {ip:18s} | {data['count']:4d} reqs | Errors: {error_count} | {label}\n"

    result += f"""
{'='*55}
          BOT DETECTION
{'='*55}
"""
    if bot_ips:
        for ip, data in bot_ips.items():
            uas = ", ".join(list(data["user_agents"])[:3])  # type: ignore
            result += f"  🤖 {ip}: {data['count']} requests\n"
            result += f"     User-Agents: {uas}\n"
            top_endpoints = data["endpoints"].most_common(3)
            result += f"     Target endpoints: {', '.join(ep for ep, _ in top_endpoints)}\n\n"
    else:
        result += "  ✅ Không phát hiện bot traffic (dựa vào user-agent)\n"

    result += f"""
{'='*55}
          POPULAR ENDPOINTS
{'='*55}
"""
    for ep, count in endpoint_hits.most_common(10):
        bar = "█" * min(count, 30)
        result += f"  {ep:35s} | {count:4d} hits {bar}\n"

    result += f"""
{'='*55}
          KHUYẾN NGHỊ
{'='*55}
"""
    if suspicious_ips:
        result += "  🚨 Có IP đáng ngờ với tỷ lệ lỗi cao → Cân nhắc chặn hoặc rate-limit\n"
    if bot_ips:
        result += "  🤖 Phát hiện bot traffic → Triển khai bot management / CAPTCHA\n"
    if peak_minute[1] > avg_rpm * 3 and avg_rpm > 0:
        result += f"  📈 Peak traffic ({peak_minute[1]} rpm) cao gấp {round(peak_minute[1] / avg_rpm, 1)}x trung bình → Cân nhắc auto-scaling\n"
    if not suspicious_ips and not bot_ips:
        result += "  ✅ Traffic patterns bình thường - không cần hành động đặc biệt\n"

    return result.strip()


# ============================================================
# TOOL 8: Generate Report - Tạo báo cáo tổng hợp
# ============================================================

def generate_report(
    security_findings: Annotated[str, "Kết quả phân tích bảo mật"],
    health_findings: Annotated[str, "Kết quả phân tích sức khỏe hệ thống"],
    performance_findings: Annotated[str, "Kết quả phân tích hiệu suất và tương quan"]
) -> str:
    """Tổng hợp tất cả kết quả phân tích từ các agent thành một báo cáo
    markdown hoàn chỉnh và lưu ra file log_analysis_report.md.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""# 📋 BÁO CÁO PHÂN TÍCH LOG SERVER
**Thời gian tạo báo cáo:** {timestamp}
**Hệ thống:** Multi-Agent Log Analyzer (Autogen Framework)

---  # type: ignore

## 1. 🛡️ Phân Tích Bảo Mật

{security_findings}

---

## 2. 🏥 Phân Tích Sức Khỏe Hệ Thống

{health_findings}

---

## 3. 📈 Phân Tích Hiệu Suất

{performance_findings}

---

## 4. 📝 Tóm Tắt & Khuyến Nghị

> Báo cáo này được tạo tự động bởi hệ thống Multi-Agent sử dụng Autogen Framework.
> Các số liệu có thể bao gồm cả metrics tính từ log entries quan sát trực tiếp và metrics summary do hệ thống tự ghi trong log.
> Một số kết luận mang tính tương quan thời gian hoặc đánh giá heuristic; cần đối chiếu trực tiếp với log gốc khi ra quyết định vận hành hoặc bảo mật.

---
*Report generated by Multi-Agent Log Analyzer System*
"""

    report_path = os.path.abspath("log_analysis_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    return f"Báo cáo đã được tạo thành công và lưu tại: {report_path}"