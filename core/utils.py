# core/utils.py
"""Utility functions for the Secure Code Analyzer."""
import os
from pathlib import Path
from typing import List, Optional

def get_file_extension(file_path: str) -> str:
    """Get the file extension from a file path."""
    return Path(file_path).suffix.lower()

def scan_directory(directory: str, extensions: List[str]) -> List[str]:
    """Scan a directory for files with specific extensions."""
    file_paths = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in extensions):
                file_paths.append(os.path.join(root, file))
    return file_paths

def is_excluded_path(path: str, exclude_patterns: List[str]) -> bool:
    """Check if a path should be excluded based on patterns."""
    path = Path(path).as_posix()
    return any(pattern in path for pattern in exclude_patterns)

def format_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"
