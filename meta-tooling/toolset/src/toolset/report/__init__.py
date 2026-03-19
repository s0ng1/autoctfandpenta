"""
Generate Word reports from verified intentlang artifacts.
"""
from core import namespace

namespace()

from .report import ReportGenerator

report = ReportGenerator()

__all__ = ['report']
