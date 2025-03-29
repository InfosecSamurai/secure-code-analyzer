# analyzer/javascript_analyzer.py
"""JavaScript code analyzer for security vulnerabilities."""
import re
from pathlib import Path
from typing import List, Dict
from .base_analyzer import BaseAnalyzer
from ..core.vulnerability_db import JAVASCRIPT_VULNERABILITIES

class JavaScriptAnalyzer(BaseAnalyzer):
    """Analyzer for JavaScript code."""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'eval': re.compile(r'eval\s*\(', re.IGNORECASE),
            'innerHTML': re.compile(r'innerHTML\s*=', re.IGNORECASE),
            'dangerous_functions': re.compile(
                r'(setTimeout|setInterval|Function)\s*\(', re.IGNORECASE),
            'no_https': re.compile(r'http:\/\/[^\s"\']+', re.IGNORECASE),
            'jquery_selector': re.compile(r'\$\([\'"].*[\'"]\)', re.IGNORECASE),
            'console_log': re.compile(r'console\.log\s*\(', re.IGNORECASE)
        }
    
    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a JavaScript file for vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        file_vulnerabilities = []
        
        for vuln_type, pattern in self.patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                vulnerability = {
                    'file_path': file_path,
                    'line_number': line_number,
                    'vulnerability_type': vuln_type,
                    'description': JAVASCRIPT_VULNERABILITIES.get(vuln_type, 'Unknown vulnerability'),
                    'code_snippet': match.group(0),
                    'severity': 'high' if vuln_type in ['eval', 'innerHTML'] else 'medium'
                }
                file_vulnerabilities.append(vulnerability)
        
        self.vulnerabilities.extend(file_vulnerabilities)
        self.stats['vulnerabilities_found'] += len(file_vulnerabilities)
        return file_vulnerabilities
    
    def is_supported_file(self, file_path: Path) -> bool:
        """Check if the file is a JavaScript file."""
        return file_path.suffix.lower() in ('.js', '.jsx', '.mjs', '.cjs')
