# analyzer/python_analyzer.py
"""Python code analyzer for security vulnerabilities."""
import ast
import re
from pathlib import Path
from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer
from ..core.vulnerability_db import PYTHON_VULNERABILITIES

class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python code."""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'eval': re.compile(r'eval\s*\(', re.IGNORECASE),
            'pickle': re.compile(r'pickle\.(loads|load)\s*\(', re.IGNORECASE),
            'shell_true': re.compile(r'subprocess\.run\(.*shell\s*=\s*True', re.IGNORECASE),
            'assert': re.compile(r'assert\s+\w+', re.IGNORECASE),
            'hardcoded_secrets': re.compile(r'(password|secret|key|token)\s*=\s*[\'"][^\'"]+[\'"]', re.IGNORECASE),
            'sql_injection': re.compile(r'cursor\.execute\s*\(.*%s', re.IGNORECASE)
        }
    
    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a Python file for vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        file_vulnerabilities = []
        
        # Pattern-based detection
        for vuln_type, pattern in self.patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                vulnerability = {
                    'file_path': file_path,
                    'line_number': line_number,
                    'vulnerability_type': vuln_type,
                    'description': PYTHON_VULNERABILITIES.get(vuln_type, 'Unknown vulnerability'),
                    'code_snippet': match.group(0),
                    'severity': 'high' if vuln_type in ['eval', 'pickle', 'shell_true'] else 'medium'
                }
                file_vulnerabilities.append(vulnerability)
        
        # AST-based detection
        try:
            tree = ast.parse(content)
            ast_vulnerabilities = self._analyze_ast(tree, file_path, content)
            file_vulnerabilities.extend(ast_vulnerabilities)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
        
        self.vulnerabilities.extend(file_vulnerabilities)
        self.stats['vulnerabilities_found'] += len(file_vulnerabilities)
        return file_vulnerabilities
    
    def _analyze_ast(self, tree: ast.AST, file_path: str, content: str) -> List[Dict]:
        """Analyze the AST for more complex vulnerabilities."""
        vulnerabilities = []
        visitor = PythonASTVisitor(file_path, content)
        visitor.visit(tree)
        vulnerabilities.extend(visitor.vulnerabilities)
        return vulnerabilities
    
    def is_supported_file(self, file_path: Path) -> bool:
        """Check if the file is a Python file."""
        return file_path.suffix.lower() in ('.py', '.pyw')

class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor for detecting Python vulnerabilities."""
    
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content = content
        self.vulnerabilities = []
    
    def visit_Call(self, node: ast.Call) -> Any:
        """Visit function calls to detect dangerous functions."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == 'eval':
                self._add_vulnerability(
                    node, 
                    'eval', 
                    'Use of eval() can lead to code injection vulnerabilities',
                    'high'
                )
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import) -> Any:
        """Visit imports to detect dangerous modules."""
        for alias in node.names:
            if alias.name == 'pickle':
                self._add_vulnerability(
                    node,
                    'pickle',
                    'Pickle can execute arbitrary code during unpickling',
                    'high'
                )
        self.generic_visit(node)
    
    def _add_vulnerability(self, node: ast.AST, vuln_type: str, 
                          description: str, severity: str) -> None:
        """Add a vulnerability to the list."""
        line_number = node.lineno
        code_lines = self.content.split('\n')
        code_snippet = code_lines[line_number - 1].strip() if line_number <= len(code_lines) else ''
        
        self.vulnerabilities.append({
            'file_path': self.file_path,
            'line_number': line_number,
            'vulnerability_type': vuln_type,
            'description': description,
            'code_snippet': code_snippet,
            'severity': severity
        })
