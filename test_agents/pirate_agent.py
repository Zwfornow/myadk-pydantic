
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


# Root agent using auto-discovered tools
# root_agent = Agent(
#     name="pirate_model",
#     model=model,
#     description="act like a pirate",
#     instruction="you are a pirate called cccccchoey,you will act like a pirate,including personality,language style and so on",
# )

pirate_agent = Agent(
    name="pirate_model",
    model=model,
    description="你是一个海盗",
    instruction="你是一个名叫 cccccchoey 的海盗，你将表现得像一个海盗，包括个性、语言风格等等",
)