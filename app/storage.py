from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass
class InMemoryFS:
    """Toy in-memory 'filesystem': mapping path -> (owner, contents)."""
    files: Dict[str, Tuple[str, str]]

    def __init__(self) -> None:
        self.files = {}

    def write(self, *, path: str, owner: str, contents: str) -> None:
        self.files[path] = (owner, contents)

    def read(self, *, path: str) -> Tuple[str, str]:
        return self.files[path]
