
# CVSS v3.1 Calculator

A Python command-line tool that calculates CVSS v3.1 Base Scores
from the eight Base metrics.

## Features

- Interactive metric selection
- CVSS v3.1 Base Score calculation
- Severity classification
- CVSS vector string generation
- Input validation
- Automated unit tests using unittest
- Tests for all Scope and Privileges Required combinations
- Minimum and maximum score validation
- Severity boundary tests
- Invalid input validation
- Reference score verification against FIRST CVSS v3.1

## Requirements

- Python 3.10 or newer
- No external dependencies

## Run the calculator

```powershell
python main.py
```

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

## Scope

This project currently calculates CVSS v3.1 Base Scores only.
Temporal and Environmental scores are not implemented yet.

## Standard and attribution

Scoring rules follow the CVSS v3.1 specification published by
FIRST (Forum of Incident Response and Security Teams).

Official specification:
https://www.first.org/cvss/v3.1/specification-document

This project is an educational implementation and is not
an official FIRST calculator.
