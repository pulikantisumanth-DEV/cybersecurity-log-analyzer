# Cybersecurity Log Analyzer & Brute-Force Detector

## Overview

Cybersecurity Log Analyzer is a Python-based defensive security tool that analyzes authentication logs and identifies suspicious login activity.

The project detects repeated failed login attempts from individual IP addresses and flags potential brute-force activity when a configurable threshold is exceeded.

## Features

- Authentication log parsing
- Successful login detection
- Failed login detection
- IP address analysis
- Username analysis
- Configurable failed-login threshold
- Possible brute-force detection
- Human-readable security report
- Command-line interface

## Technologies

- Python 3
- Regular Expressions
- Collections / Counter
- Argparse
- File I/O

## Project Architecture

```text
Authentication Logs
        |
        v
   Log Parser
        |
        v
 Event Classification
        |
        v
Failed Login Counter
        |
        v
Suspicious IP Detection
        |
        v
 Security Report
