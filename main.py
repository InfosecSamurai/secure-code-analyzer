# main.py
"""Main entry point for the Secure Code Analyzer."""
import argparse
from analyzer.javascript_analyzer import JavaScriptAnalyzer
from analyzer.python_analyzer import PythonAnalyzer

def main():
    """Main function for the Secure Code Analyzer."""
    parser = argparse.ArgumentParser(
        description='Secure Code Analyzer - Tool for analyzing web code for security vulnerabilities and best practices.'
    )
    parser.add_argument('path', help='Path to the directory or file to analyze')
    parser.add_argument('-l', '--language', choices=['js', 'python', 'all'], 
                        default='all', help='Language to analyze')
    parser.add_argument('-o', '--output', help='Output file for results')
    args = parser.parse_args()
    
    analyzers = []
    if args.language in ['js', 'all']:
        analyzers.append(JavaScriptAnalyzer())
    if args.language in ['python', 'all']:
        analyzers.append(PythonAnalyzer())
    
    for analyzer in analyzers:
        if Path(args.path).is_file():
            analyzer.analyze_file(args.path)
        else:
            analyzer.analyze_directory(args.path)
        
        analyzer.print_summary()
        if args.output:
            analyzer.save_results(args.output)
        else:
            analyzer.save_results()

if __name__ == '__main__':
    from pathlib import Path
    main()
