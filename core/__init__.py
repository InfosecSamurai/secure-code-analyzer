# core/__init__.py
"""Initialization file for the core module."""
from .config import Config
from .utils import scan_directory
from .vulnerability_db import JAVASCRIPT_VULNERABILITIES, PYTHON_VULNERABILITIES

__all__ = ['Config', 'scan_directory', 'JAVASCRIPT_VULNERABILITIES', 'PYTHON_VULNERABILITIES']
