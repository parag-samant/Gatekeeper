"""Advisory package for security advisory generation."""

from .generator import AdvisoryGenerator
from .prompts import ADVISORY_SYSTEM_PROMPT

__all__ = ["AdvisoryGenerator", "ADVISORY_SYSTEM_PROMPT"]
