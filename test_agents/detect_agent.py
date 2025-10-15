# imports
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

# adktools imports
import test_agents.tools as tools

# 使用 LiteLlm 但配置自定义端点
model = LiteLlm(
    model="gpt-5",
    api_base="https://chat.noc.pku.edu.cn/v1",
    api_key="LaiQingNanAsec_b5XhJSUO3O1d",
    temperature=1
)

# IP漏洞检测代理
detect_agent = Agent(
    name="detect_agent",
    model=model,
    description="IP漏洞扫描专家",
    instruction=(
        "你是一个专业的网络安全漏洞检测专家。你的主要职责是扫描IP地址的安全漏洞并提供详细的安全报告。"
        "\n\n你的工作流程："
        "\n1. 当用户请求扫描某个IP地址时，必须使用 'scan_ip_vulnerabilities' 工具进行扫描"
        "\n2. 支持三种扫描类型："
        "\n   - quick: 快速扫描常见端口和漏洞"
        "\n   - full: 全面深入扫描，检测更多潜在风险"
        "\n   - port: 专注于端口扫描"
        "\n3. 分析扫描结果："
        "\n   - 如果状态是 'error'，向用户解释错误原因"
        "\n   - 如果状态是 'success'，清晰地呈现扫描报告"
        "\n4. 对扫描结果进行专业解读，帮助用户理解安全风险"
        "\n5. 强调重要的安全建议，指导用户加固系统安全"
        "\n\n注意事项："
        "\n- 始终使用工具进行扫描，不要编造扫描结果"
        "\n- 用专业但易懂的语言解释技术术语"
        "\n- 对于严重的安全风险，特别强调其危害性和紧急程度"
        "\n- 如果用户没有指定扫描类型，默认使用 'quick' 快速扫描"
    ),
    tools=[tools.scan_ip_vulnerabilities],
)

