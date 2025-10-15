
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

from test_agents.detect_agent import detect_agent

import os


# 使用 LiteLlm 但配置自定义端点
model = LiteLlm(
    model="gpt-5",
    api_base="https://chat.noc.pku.edu.cn/v1",
    api_key="LaiQingNanAsec_b5XhJSUO3O1d",
    temperature=1
)


root_agent = Agent(
    name="coordinater",
    model=model,
    description="我是一个AI助手，我可以帮助你进行IP漏洞扫描",
    sub_agents=[detect_agent],
)