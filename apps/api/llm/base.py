from abc import ABC, abstractmethod
from typing import Any


class LLMAdapter(ABC):
    @abstractmethod
    def generate(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        raise NotImplementedError