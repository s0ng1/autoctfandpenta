"""
Generate HTML reports with vulnerability details and embedded screenshots.
"""
from core import namespace

namespace()

from .report import ReportGenerator

report = ReportGenerator()

__all__ = ['report']
