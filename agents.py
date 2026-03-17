"""
agents.py - Định nghĩa tất cả agents và GroupChat cho hệ thống Multi-Agent phân tích log server.
Sử dụng Autogen framework với GroupChat và GroupChatManager.
Hỗ trợ đa định dạng log: Custom Application Log, Nginx, Apache, Syslog.

Agents:
  1. Admin (UserProxyAgent) - Điểm bắt đầu, executor cho tools
  2. Log_Parser - Phân tích cú pháp và cấu trúc log
  3. Security_Analyst - Phân tích bảo mật và lỗ hổng
  4. System_Health_Analyst - Phân tích sức khỏe hệ thống
  5. Performance_Expert - Phân tích hiệu suất
  6. Correlation_Analyst - Phân tích tương quan sự kiện và traffic
  7. Final_Reporter - Tổng hợp báo cáo
"""

import os
from dotenv import load_dotenv
import autogen
from tools import (
    parse_log_file,
    extract_error_entries,
    detect_security_threats,
    scan_vulnerabilities,
    analyze_system_health,
    analyze_performance,
    correlate_events,
    analyze_traffic_patterns,
    generate_report,
)

load_dotenv()


def get_llm_config():
    """Cấu hình LLM dựa trên biến môi trường có sẵn."""
    if os.environ.get("OPENAI_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("OPENAI_MODEL", "gpt-4o"),
                "api_key": os.environ["OPENAI_API_KEY"],
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    if os.environ.get("GOOGLE_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("GOOGLE_MODEL", "gemini-2.0-flash"),
                "api_key": os.environ["GOOGLE_API_KEY"],
                "api_type": "google",
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    if os.environ.get("DEEPSEEK_API_KEY"):
        return {
            "config_list": [{
                "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
                "api_key": os.environ["DEEPSEEK_API_KEY"],
                "base_url": "https://api.deepseek.com/v1",
                "price": [0, 0],
            }],
            "temperature": 0.0,
            "timeout": 120,
            "cache_seed": 42,
        }

    raise ValueError(
        "Không tìm thấy API key! Vui lòng đặt một trong các biến môi trường:\n"
        "  - OPENAI_API_KEY\n"
        "  - GOOGLE_API_KEY\n"
        "  - DEEPSEEK_API_KEY\n"
    )


def create_agents_and_groupchat(log_file_path: str):
    """Tạo tất cả agents, đăng ký tools, và thiết lập GroupChat."""
    llm_config = get_llm_config()

    # ========================================================
    # 1. ADMIN
    # ========================================================
    admin = autogen.UserProxyAgent(
        name="Admin",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=12,
        is_termination_msg=lambda x: x.get("content", "") and "TERMINATE" in x.get("content", ""),
        code_execution_config=False,
        system_message=f"""Role: Admin
Log file: {log_file_path}

Rules:
- Execute tools only when another agent calls them.
- Do not analyze the log.
- Do not write the report.
- End when Final_Reporter finishes.""",
    )

    # ========================================================
    # 2. LOG PARSER
    # ========================================================
    log_parser = autogen.AssistantAgent(
        name="Log_Parser",
        llm_config=llm_config,
        system_message=f"""Role: Log_Parser
Log file: {log_file_path}

Allowed tools:
- parse_log_file
- extract_error_entries

Rules:
- Use only these tools.
- Do not use other agents' tools.
- Do not delegate tasks.
- If selected as speaker, do only the next unfinished step of Log_Parser.
- Use tool outputs only. Do not read the file directly.
- Do not say "KHÔNG THUỘC NHIỆM VỤ CỦA TÔI" or "CHƯA ĐẾN LƯỢT CỦA TÔI".

Workflow:
1. Call parse_log_file
2. Call extract_error_entries
3. Write summary and stop

Output:

[LOG_PARSER_SUMMARY]
- Log type:
- Log format:
- Total lines:
- Time range:
- Key services:
- Key IPs:
- Key endpoints:
- Important log events:

[ERROR_SUMMARY]
- Total CRITICAL:
- Total ERROR:
- Main services with errors:
- Important error examples:

If data is missing, write:
KHÔNG ĐỦ DỮ LIỆU.""",
    )

    # ========================================================
    # 3. SECURITY ANALYST
    # ========================================================
    security_analyst = autogen.AssistantAgent(
        name="Security_Analyst",
        llm_config=llm_config,
        system_message=f"""Role: Security_Analyst
Log file: {log_file_path}

Allowed tools:
- detect_security_threats
- scan_vulnerabilities

Rules:
- Use only these tools.
- Do not use other agents' tools.
- Do not delegate tasks.
- If selected as speaker, do only the next unfinished step of Security_Analyst.
- Base conclusions only on tool outputs.
- Do not say "KHÔNG THUỘC NHIỆM VỤ CỦA TÔI" or "CHƯA ĐẾN LƯỢT CỦA TÔI".

Focus:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Brute-force
- Unauthorized access
- Recon activity
- DoS / flooding

Workflow:
1. Call detect_security_threats
2. Call scan_vulnerabilities
3. Write summary and stop

Output:

[SECURITY_FINDINGS]
- Total attack events:
- Attack types detected:
- Suspicious IPs:
- Targeted services/endpoints:
- Attack timeline:
- Risk assessment:
- Evidence from log:
- KHÔNG ĐỦ DỮ LIỆU:""",
    )

    # ========================================================
    # 4. SYSTEM HEALTH ANALYST
    # ========================================================
    system_health_analyst = autogen.AssistantAgent(
        name="System_Health_Analyst",
        llm_config=llm_config,
        system_message=f"""Role: System_Health_Analyst
Log file: {log_file_path}

Allowed tool:
- analyze_system_health

Rules:
- Use only this tool.
- Do not use other agents' tools.
- Do not delegate tasks.
- If selected as speaker, do only the next unfinished step of System_Health_Analyst.
- Use tool results only.
- Do not say "KHÔNG THUỘC NHIỆM VỤ CỦA TÔI" or "CHƯA ĐẾN LƯỢT CỦA TÔI".

Workflow:
1. Call analyze_system_health
2. Write summary and stop

Output:

[HEALTH_FINDINGS]
- Overall health status:
- CPU usage:
- Memory usage:
- Disk usage:
- Health warnings:
- Health critical events:
- Service issues:
- Important system events:

If metrics do not exist in log, write:
KHÔNG ĐỦ DỮ LIỆU.""",
    )

    # ========================================================
    # 5. PERFORMANCE EXPERT
    # ========================================================
    performance_expert = autogen.AssistantAgent(
        name="Performance_Expert",
        llm_config=llm_config,
        system_message=f"""Role: Performance_Expert
Log file: {log_file_path}

Allowed tool:
- analyze_performance

Rules:
- Use only this tool.
- Do not use other agents' tools.
- Do not delegate tasks.
- If selected as speaker, do only the next unfinished step of Performance_Expert.
- Your final summary must start exactly with [PERFORMANCE_FINDINGS].
- After sending [PERFORMANCE_FINDINGS], stop immediately.
- Do not send a second summary for the same phase.
- Do not say "KHÔNG THUỘC NHIỆM VỤ CỦA TÔI" or "CHƯA ĐẾN LƯỢT CỦA TÔI".

Workflow:
1. Call analyze_performance
2. Write summary and stop

Output:

[PERFORMANCE_FINDINGS]
- Total HTTP requests:
- Response time summary:
- Error rate:
- Slow requests:
- Slow endpoints:
- Throughput:
- Server summary metrics:
- KHÔNG ĐỦ DỮ LIỆU:""",
    )

    # ========================================================
    # 6. CORRELATION ANALYST
    # ========================================================
    correlation_analyst = autogen.AssistantAgent(
        name="Correlation_Analyst",
        llm_config=llm_config,
        system_message=f"""Role: Correlation_Analyst
Log file: {log_file_path}

Allowed tools:
- correlate_events
- analyze_traffic_patterns

Rules:
- Use only these tools.
- Do not use other agents' tools.
- Do not delegate tasks.
- Never call analyze_correlation.
- If selected as speaker, do only the next unfinished step of Correlation_Analyst.
- Temporal correlation does NOT prove causation.
- Use cautious wording only.
- Do not say "KHÔNG THUỘC NHIỆM VỤ CỦA TÔI" or "CHƯA ĐẾN LƯỢT CỦA TÔI".

Focus:
- error cascades
- attack → impact temporal correlation
- traffic anomalies
- suspicious IP patterns

Workflow:
1. Call correlate_events
2. Call analyze_traffic_patterns
3. Write summary and stop

Output:

[CORRELATION_FINDINGS]
- Error cascades:
- Attack / impact correlation:
- Resource / event correlation:
- Traffic anomalies:
- Suspicious IP traffic patterns:
- Timeline relationships:
- KHÔNG ĐỦ DỮ LIỆU:""",
    )

    # ========================================================
    # 7. FINAL REPORTER
    # ========================================================
    final_reporter = autogen.AssistantAgent(
        name="Final_Reporter",
        llm_config=llm_config,
        system_message="""Role: Final_Reporter

Allowed tool:
- generate_report

Rules:
- Use only this tool.
- Do not use other agents' tools.
- Do not delegate tasks.
- Do not print the full report in chat.
- If selected as speaker, create the report immediately.

Input comes from:
- [SECURITY_FINDINGS]
- [HEALTH_FINDINGS]
- [PERFORMANCE_FINDINGS]
- [CORRELATION_FINDINGS]

Workflow:
1. Merge correlation into performance_findings
2. Call:

generate_report(
    security_findings=...,
    health_findings=...,
    performance_findings=...
)

After tool succeeds, reply exactly:
Báo cáo đã hoàn thành. TERMINATE""",
    )

    # ========================================================
    # ĐĂNG KÝ TOOLS
    # ========================================================
    def register_tool(caller, func, name, description):
        caller.register_for_llm(name=name, description=description)(func)
        admin.register_for_execution(name=name)(func)

    # ---------- LOG PARSER ----------
    register_tool(
        log_parser,
        parse_log_file,
        "parse_log_file",
        "Đọc và phân tích tổng quan file log server."
    )
    register_tool(
        log_parser,
        extract_error_entries,
        "extract_error_entries",
        "Trích xuất tất cả dòng log ERROR hoặc CRITICAL."
    )

    # ---------- SECURITY ----------
    register_tool(
        security_analyst,
        detect_security_threats,
        "detect_security_threats",
        "Phát hiện các dấu hiệu tấn công bảo mật như SQL injection, XSS, brute force."
    )
    register_tool(
        security_analyst,
        scan_vulnerabilities,
        "scan_vulnerabilities",
        "Phân tích sâu các lỗ hổng bảo mật và timeline tấn công."
    )

    # ---------- SYSTEM HEALTH ----------
    register_tool(
        system_health_analyst,
        analyze_system_health,
        "analyze_system_health",
        "Phân tích sức khỏe hệ thống từ log."
    )

    # ---------- PERFORMANCE ----------
    register_tool(
        performance_expert,
        analyze_performance,
        "analyze_performance",
        "Phân tích hiệu suất hệ thống: response time, throughput, error rate."
    )

    # ---------- CORRELATION ----------
    register_tool(
        correlation_analyst,
        correlate_events,
        "correlate_events",
        "Phân tích tương quan giữa các sự kiện trong log."
    )
    register_tool(
        correlation_analyst,
        analyze_traffic_patterns,
        "analyze_traffic_patterns",
        "Phân tích traffic patterns và IP đáng ngờ."
    )

    # ---------- FINAL REPORT ----------
    register_tool(
        final_reporter,
        generate_report,
        "generate_report",
        "Tổng hợp kết quả phân tích thành báo cáo markdown."
    )

    # ========================================================
    # CUSTOM SPEAKER SELECTION - QUY TRÌNH CỐ ĐỊNH
    # ========================================================
    def custom_speaker_selection(last_speaker, groupchat):
        messages = groupchat.messages
        if not messages:
            return admin

        last_msg = messages[-1]
        last_content = str(last_msg.get("content", "") or "")
        all_text = "\n".join(str(m.get("content", "") or "") for m in messages)

        name_to_agent = {
            "Log_Parser": log_parser,
            "Security_Analyst": security_analyst,
            "System_Health_Analyst": system_health_analyst,
            "Performance_Expert": performance_expert,
            "Correlation_Analyst": correlation_analyst,
            "Final_Reporter": final_reporter,
        }

        def has_text(text: str) -> bool:
            return text in all_text

        def message_requests_tool(msg) -> bool:
            content = str(msg.get("content", "") or "")
            if msg.get("tool_calls") or msg.get("function_call"):
                return True
            if "Suggested tool call" in content:
                return True
            if '<｜DSML｜invoke name="' in content:
                return True
            return False

        def is_tool_response(msg) -> bool:
            content = str(msg.get("content", "") or "")
            role = str(msg.get("role", "") or "")
            return (
                role in ("tool", "function")
                or "Response from calling tool" in content
                or "Error:" in content
            )

        # 1. Agent vừa gọi tool -> Admin thực thi
        if last_speaker is not admin and message_requests_tool(last_msg):
            return admin

        # 2. Admin vừa trả tool result -> trả lại đúng agent trước đó
        if last_speaker is admin and is_tool_response(last_msg):
            if len(messages) >= 2:
                prev_name = messages[-2].get("name", "")
                return name_to_agent.get(prev_name, log_parser)
            return log_parser

        # 3. Nếu Final_Reporter đã terminate -> dừng
        if last_speaker is final_reporter and "TERMINATE" in last_content:
            return None

        # 4. Chuyển phase ngay sau khi summary đã có
        if last_speaker is log_parser:
            if has_text("[LOG_PARSER_SUMMARY]") and has_text("[ERROR_SUMMARY]"):
                return security_analyst
            return log_parser

        if last_speaker is security_analyst:
            if has_text("[SECURITY_FINDINGS]"):
                return system_health_analyst
            return security_analyst

        if last_speaker is system_health_analyst:
            if has_text("[HEALTH_FINDINGS]"):
                return performance_expert
            return system_health_analyst

        if last_speaker is performance_expert:
            if has_text("[PERFORMANCE_FINDINGS]"):
                return correlation_analyst
            return performance_expert

        if last_speaker is correlation_analyst:
            if has_text("[CORRELATION_FINDINGS]"):
                return final_reporter
            return correlation_analyst

        if last_speaker is final_reporter:
            return final_reporter

        # 5. Fallback theo pipeline toàn cục
        if not has_text("===== BÁO CÁO PHÂN TÍCH TỔNG QUAN LOG ====="):
            return log_parser

        if not has_text("===== TRÍCH XUẤT LỖI (ERROR/CRITICAL) ====="):
            return log_parser

        if not has_text("[LOG_PARSER_SUMMARY]") or not has_text("[ERROR_SUMMARY]"):
            return log_parser

        if not has_text("===== BÁO CÁO PHÂN TÍCH BẢO MẬT CHI TIẾT ====="):
            return security_analyst

        if not has_text("===== BÁO CÁO QUÉT LỖ HỔNG BẢO MẬT CHUYÊN SÂU ====="):
            return security_analyst

        if not has_text("[SECURITY_FINDINGS]"):
            return security_analyst

        if not has_text("===== BÁO CÁO SỨC KHỎE HỆ THỐNG ====="):
            return system_health_analyst

        if not has_text("[HEALTH_FINDINGS]"):
            return system_health_analyst

        if not has_text("===== BÁO CÁO PHÂN TÍCH HIỆU SUẤT ====="):
            return performance_expert

        if not has_text("[PERFORMANCE_FINDINGS]"):
            return performance_expert

        if not has_text("===== BÁO CÁO PHÂN TÍCH TƯƠNG QUAN SỰ KIỆN ====="):
            return correlation_analyst

        if not has_text("===== BÁO CÁO PHÂN TÍCH TRAFFIC PATTERNS ====="):
            return correlation_analyst

        if not has_text("[CORRELATION_FINDINGS]"):
            return correlation_analyst

        if not has_text("Báo cáo đã được tạo thành công và lưu tại:"):
            return final_reporter

        return final_reporter

    # ========================================================
    # THIẾT LẬP GROUP CHAT
    # ========================================================
    agents = [
        admin,
        log_parser,
        security_analyst,
        system_health_analyst,
        performance_expert,
        correlation_analyst,
        final_reporter,
    ]

    group_chat = autogen.GroupChat(
        agents=agents,
        messages=[],
        max_round=24,
        speaker_selection_method=custom_speaker_selection,
        allow_repeat_speaker=False,
    )

    group_chat_manager = autogen.GroupChatManager(
        groupchat=group_chat,
        llm_config=llm_config,
        is_termination_msg=lambda x: x.get("content", "") and "TERMINATE" in x.get("content", ""),
    )

    return admin, group_chat_manager