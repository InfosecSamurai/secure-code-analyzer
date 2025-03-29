# analyzer/base_analyzer.py
"""Base analyzer class providing common functionality for all analyzers."""
from abc import ABC, abstractmethod
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
from ..core.utils import get_file_extension

class BaseAnalyzer(ABC):
    """Abstract base class for all code analyzers."""
    
    def __init__(self):
        self.vulnerabilities = []
        self.stats = {
            'files_scanned': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }
    
    @abstractmethod
    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a single file for vulnerabilities."""
        pass
    
    def analyze_directory(self, directory_path: str) -> List[Dict]:
        """Analyze all files in a directory."""
        self.stats['start_time'] = datetime.now()
        path = Path(directory_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        for file_path in path.rglob('*'):
            if file_path.is_file() and self.is_supported_file(file_path):
                self.analyze_file(str(file_path))
                self.stats['files_scanned'] += 1
        
        self.stats['end_time'] = datetime.now()
        return self.vulnerabilities
    
    @abstractmethod
    def is_supported_file(self, file_path: Path) -> bool:
        """Check if the file is supported by this analyzer."""
        pass
    
    def save_results(self, output_path: str = 'output/results.json'):
        """Save analysis results to a JSON file."""
        output = {
            'stats': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
        
        Path(output_path).parent.mkdir(exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2, default=str)
    
    def print_summary(self):
        """Print a summary of the analysis."""
        duration = self.stats['end_time'] - self.stats['start_time']
        print(f"\nAnalysis Summary:")
        print(f"  Files scanned: {self.stats['files_scanned']}")
        print(f"  Vulnerabilities found: {self.stats['vulnerabilities_found']}")
        print(f"  Time taken: {duration}")
