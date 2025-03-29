# tests/test_javascript_analyzer.py
"""Tests for the JavaScript analyzer."""
import os
import tempfile
import unittest
from analyzer.javascript_analyzer import JavaScriptAnalyzer

class TestJavaScriptAnalyzer(unittest.TestCase):
    """Test cases for JavaScriptAnalyzer."""
    
    def setUp(self):
        self.analyzer = JavaScriptAnalyzer()
        self.test_dir = tempfile.mkdtemp()
    
    def test_eval_detection(self):
        """Test detection of eval() usage."""
        test_file = os.path.join(self.test_dir, 'test.js')
        with open(test_file, 'w') as f:
            f.write('eval("alert(\'test\')");')
        
        results = self.analyzer.analyze_file(test_file)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['vulnerability_type'], 'eval')
    
    def test_innerHTML_detection(self):
        """Test detection of innerHTML usage."""
        test_file = os.path.join(self.test_dir, 'test.js')
        with open(test_file, 'w') as f:
            f.write('document.getElementById("test").innerHTML = "<script>alert(1)</script>";')
        
        results = self.analyzer.analyze_file(test_file)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['vulnerability_type'], 'innerHTML')
    
    def tearDown(self):
        """Clean up test files."""
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

if __name__ == '__main__':
    unittest.main()
