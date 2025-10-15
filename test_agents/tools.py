# test_agent/tools.py
import datetime
from zoneinfo import ZoneInfo
from pydantic import ValidationError
import re
import random

from .models import ScanRequest, ScanResult, ScanData






def scan_ip_vulnerabilities(ip_address: str, scan_type: str = "quick") -> dict:
    """扫描指定IP地址的漏洞并生成安全报告。

    参数:
        ip_address (str): 要扫描的IP地址（如"192.168.1.1"）
        scan_type (str): 扫描类型 - "quick"（快速）、"full"（全面）、"port"（端口扫描）

    返回:
        dict: {"status": "success", "report": str, "data": dict} 或 {"status": "error", "error_message": str}
    """

    # 使用 pydantic 验证输入（同时保持向后兼容的错误 dict 返回）
    try:
        req = ScanRequest(ip_address=ip_address, scan_type=scan_type)
    except ValidationError as e:
        return {"status": "error", "error_message": e.errors()}

    # 验证IP地址的每个段是否在0-255范围内
    parts = ip_address.split('.')
    for part in parts:
        if int(part) > 255 or int(part) < 0:
            return {
                "status": "error",
                "error_message": f"无效的IP地址：{ip_address}。每段数字必须在0-255之间"
            }

    # 模拟扫描过程（在实际应用中，这里会调用真实的漏洞扫描工具）
    scan_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 根据扫描类型模拟不同的扫描结果
    if scan_type == "quick":
        # 快速扫描：检查常见端口
        open_ports = [port for port in [22, 80, 443, 3306, 8080] if random.random() > 0.5]
        vulnerabilities = []
        
        if 22 in open_ports:
            vulnerabilities.append("SSH服务开放 - 可能存在弱密码风险")
        if 3306 in open_ports:
            vulnerabilities.append("MySQL数据库端口开放 - 建议配置防火墙限制访问")
        if 80 in open_ports and 443 not in open_ports:
            vulnerabilities.append("仅HTTP开放，未启用HTTPS - 数据传输不加密")
            
    elif scan_type == "full":
        # 全面扫描：检查更多端口和漏洞
        open_ports = [port for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443] 
                     if random.random() > 0.4]
        vulnerabilities = []
        
        if 21 in open_ports:
            vulnerabilities.append("FTP服务开放 - 存在明文传输风险")
        if 23 in open_ports:
            vulnerabilities.append("Telnet服务开放 - 严重安全隐患，建议立即关闭")
        if 22 in open_ports:
            vulnerabilities.append("SSH服务开放 - 建议使用密钥认证，禁用密码登录")
        if 3306 in open_ports:
            vulnerabilities.append("MySQL数据库直接暴露 - 严重安全风险")
        if 3389 in open_ports:
            vulnerabilities.append("RDP远程桌面开放 - 可能遭受暴力破解攻击")
        if 80 in open_ports and 443 not in open_ports:
            vulnerabilities.append("Web服务未启用HTTPS - 数据传输不安全")
        
        # 添加一些额外的漏洞检测
        if random.random() > 0.6:
            vulnerabilities.append("检测到过期的SSL/TLS版本 - 建议升级到TLS 1.2或更高版本")
        if random.random() > 0.7:
            vulnerabilities.append("防火墙配置可能过于宽松 - 建议实施最小权限原则")
            
    elif scan_type == "port":
        # 端口扫描：专注于端口检测
        open_ports = [port for port in range(1, 65536) if random.random() > 0.9999][:15]
        vulnerabilities = [f"发现 {len(open_ports)} 个开放端口"]
        
    else:
        return {
            "status": "error",
            "error_message": f"不支持的扫描类型：{scan_type}。支持的类型：quick, full, port"
        }

    # 评估风险等级
    risk_level = "low"
    if len(vulnerabilities) == 0:
        risk_level = "low"
    elif len(vulnerabilities) <= 2:
        risk_level = "medium"
    elif len(vulnerabilities) <= 4:
        risk_level = "high"
    else:
        risk_level = "critical"
    
    # 如果检测到高危端口，提升风险等级
    critical_ports = [23, 3389]
    if any(port in open_ports for port in critical_ports):
        risk_level = "critical"

    # 生成安全建议
    recommendations = []
    if 23 in open_ports:
        recommendations.append("立即关闭Telnet服务，使用SSH替代")
    if 3389 in open_ports:
        recommendations.append("限制RDP访问，仅允许特定IP地址连接")
    if 3306 in open_ports or 5432 in open_ports:
        recommendations.append("数据库服务不应直接暴露在公网，建议配置VPN或跳板机")
    if 80 in open_ports and 443 not in open_ports:
        recommendations.append("启用HTTPS加密，申请SSL证书")
    if 22 in open_ports:
        recommendations.append("配置SSH密钥认证，禁用root用户直接登录")
    
    recommendations.append("定期更新系统和软件补丁")
    recommendations.append("配置防火墙规则，关闭不必要的端口")
    recommendations.append("启用入侵检测系统(IDS)监控异常活动")

    # 构建扫描数据并使用 pydantic 模型包装
    scan_data = ScanData(
        ip_address=req.ip_address,
        scan_type=req.scan_type,
        open_ports=sorted(open_ports),
        vulnerabilities=vulnerabilities,
        risk_level=risk_level,
        recommendations=recommendations,
        scan_timestamp=scan_timestamp,
    )

    # 生成报告文本
    risk_level_cn = {
        "low": "低风险 ✓",
        "medium": "中等风险 ⚠",
        "high": "高风险 ⚠⚠",
        "critical": "严重风险 ❗❗"
    }
    
    report_lines = [
        f"\n═══════════════════════════════════════",
        f"        IP漏洞扫描报告",
        f"═══════════════════════════════════════",
        f"",
        f"📍 目标IP: {ip_address}",
        f"🔍 扫描类型: {scan_type}",
        f"⏰ 扫描时间: {scan_timestamp}",
        f"🎯 风险等级: {risk_level_cn[risk_level]}",
        f"",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🔓 开放端口 ({len(open_ports)}个):",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ]
    
    if open_ports:
        report_lines.append(f"   {', '.join(map(str, open_ports))}")
    else:
        report_lines.append("   无开放端口")
    
    report_lines.extend([
        f"",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"⚠️  发现的漏洞 ({len(vulnerabilities)}个):",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ])
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            report_lines.append(f"   {i}. {vuln}")
    else:
        report_lines.append("   ✓ 未发现明显漏洞")
    
    report_lines.extend([
        f"",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"💡 安全建议:",
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ])
    
    for i, rec in enumerate(recommendations, 1):
        report_lines.append(f"   {i}. {rec}")
    
    report_lines.extend([
        f"",
        f"═══════════════════════════════════════",
        f"报告生成完毕",
        f"═══════════════════════════════════════\n",
    ])
    
    report = "\n".join(report_lines)

    result = ScanResult(status="success", report=report, data=scan_data)
    # 保持与现有代码兼容：返回 dict（可以通过 .dict() 获取序列化结构）
    return result.dict()