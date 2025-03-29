# tests/test_python_analyzer.py
"""Tests for the Python analyzer."""
import os
import tempfile
import unittest
from analyzer.python_analyzer import PythonAnalyzer

class TestPythonAnalyzer(unittest.TestCase):
    """Test cases for PythonAnalyzer."""
    
    def setUp(self):
        self.analyzer = PythonAnalyzer()
        self.test_dir = tempfile.mkdtemp()
    
    def test_eval_detection(self):
        """Test detection of eval() usage."""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('eval("print(\'test\')")')
        
        results = self.analyzer.analyze_file(test_file)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['vulnerability_type'], 'eval')
    
    def test_pickle_detection(self):
        """Test detection of pickle usage."""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('import pickle\npickle.loads(data)')
        
        results = self.analyzer.analyze_file(test_file)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['vulnerability_type'], 'pickle')
    
    def tearDown(self):
        """Clean up test files."""
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

if __name__ == '__main__':
    unittest.main()
