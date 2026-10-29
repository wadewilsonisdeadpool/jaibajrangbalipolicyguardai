from typing import Any

from apps.api.llm.base import LLMAdapter
from apps.api.tool_broker import ToolBroker, ToolRequest


class AgentRuntime:
    def __init__(
        self,
        llm: LLMAdapter,
        tool_broker: ToolBroker,
    ) -> None:
        self.llm = llm
        self.tool_broker = tool_broker

    def run(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        agent_id: int,
        tool_request: ToolRequest | None = None,
    ) -> dict[str, Any]:
        model_result = self.llm.generate(
            messages=messages,
            tools=tools,
        )

        result: dict[str, Any] = {
            "agent_id": agent_id,
            "model_output": model_result,
        }

        if tool_request is not None:
            result["security_decision"] = self.tool_broker.request_tool(
                tool_request
            )

        return result