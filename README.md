# Secure Code Analyzer

A tool for analyzing JavaScript and Python code for security vulnerabilities and best practices.

## Features

- Detects common security vulnerabilities in JavaScript and Python code
- Provides detailed reports with vulnerability descriptions and severity levels
- Supports both file and directory analysis
- Configurable through JSON configuration files

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`

## Usage

```bash
python main.py <path> [options]

Options:
  -l, --language {js,python,all}  Language to analyze (default: all)
  -o, --output OUTPUT            Output file for results
```
Examples

Analyze a JavaScript project:
```bash
python main.py /path/to/js/project -l js -o js_report.json
```
Analyze a Python file:
```bash
python main.py /path/to/python/file.py -l python
```
Analyze all supported languages in a directory:
```bash
python main.py /path/to/project
```
### Supported Vulnerabilities

**JavaScript**

  - eval() usage

  - innerHTML assignments

  - Dangerous functions (setTimeout, setInterval, Function)

  - HTTP URLs

  - jQuery selectors

  - Console.log statements

**Python**

  - eval() usage

  - pickle module usage

  - shell=True in subprocess

  - Assert statements

  - Hardcoded secrets

  - SQL injection patterns
