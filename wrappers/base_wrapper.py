"""Abstract base wrapper - unified interface for every security tool."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional


class BaseWrapper(ABC):
    """Common interface hiding the differences between tools."""

    naziv: str = "base"

    def __init__(self, config: dict):
        self.config = config or {}

    @abstractmethod
    def run(self, target: str, output_dir: Path, **kwargs: Any) -> Optional[Path]:
        """Run the tool and return the path to its raw output (or None on failure)."""
        raise NotImplementedError
