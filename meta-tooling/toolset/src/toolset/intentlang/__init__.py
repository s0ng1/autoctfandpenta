"""
Structured access to intent-native metadata and artifacts in the workspace.
"""
from core import namespace

namespace()

from .intentlang import IntentLangMemory

intentlang = IntentLangMemory()

__all__ = ["intentlang"]
