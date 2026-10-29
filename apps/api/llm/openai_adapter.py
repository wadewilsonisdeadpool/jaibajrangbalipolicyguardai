import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from apps.api.llm.base import LLMAdapter


# Load the .env file located at:
# apps/api/.env
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_PATH)


class OpenAIAdapter(LLMAdapter):
    def __init__(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key or api_key == "your_api_key_here":
            raise RuntimeError("OPENAI_API_KEY is not configured")

        self.client = OpenAI(api_key=api_key)

    def generate(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        response = self.client.responses.create(
            model="gpt-5.1",
            input=messages,
            tools=tools,
        )

        return {
            "response_id": response.id,
            "output": response.output,
        }