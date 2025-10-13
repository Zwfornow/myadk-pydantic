
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

import os


# 使用 LiteLlm 但配置自定义端点
model = LiteLlm(
    model="gpt-5",
    api_base="https://chat.noc.pku.edu.cn/v1",
    api_key="LaiQingNanAsec_b5XhJSUO3O1d",
    temperature=1
)

root_agent = Agent(
    name="detect_model",
    model=model,
    description="你是一个侦探",
    instruction="你是一个名叫 cccccchoey 的侦探，你将表现得像一个侦探，包括个性、语言风格等等",
)