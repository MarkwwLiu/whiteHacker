# WhiteHats - Automated White Hat Security Testing Framework

Python-based automated white hat security testing framework. Provide an API endpoint or URL, and it auto-generates and runs security test cases.

## Architecture

```
whiteHacker/
├── config/
│   ├── default_config.yaml        # Default scan settings
│   └── targets_example.json       # Example targets file
├── whitehats/                     # Core framework package
│   ├── cli.py                     # CLI entry point
│   ├── config.py                  # Configuration loader
│   ├── models/                    # Data models
│   │   ├── target.py              # Target (API/URL) models
│   │   ├── vulnerability.py       # Vulnerability finding model
│   │   └── test_case.py           # Test case model
│   ├── scanner/                   # Scan engine
│   │   ├── base_scanner.py        # Abstract base scanner
│   │   ├── api_scanner.py         # API endpoint scanner
│   │   └── url_scanner.py         # URL page scanner
│   ├── modules/                   # Security test modules (pluggable)
│   │   ├── base_module.py         # Abstract base module
│   │   ├── sql_injection.py       # SQL Injection detection
│   │   ├── xss.py                 # Cross-Site Scripting detection
│   │   ├── csrf.py                # CSRF protection check
│   │   ├── header_security.py     # Security headers audit
│   │   ├── cors_misconfig.py      # CORS misconfiguration check
│   │   └── info_disclosure.py     # Information disclosure check
│   ├── generator/                 # Test case auto-generator
│   │   ├── test_generator.py      # Generates pytest files
│   │   └── template_engine.py     # Test file templates
│   ├── payloads/                  # Attack payload data
│   │   ├── sql_payloads.txt
│   │   └── xss_payloads.txt
│   └── reporter/                  # Report generation
│       ├── base_reporter.py
│       ├── json_reporter.py       # JSON report output
│       └── html_reporter.py       # HTML report output
├── test_cases/                    # Auto-generated test cases (decoupled)
├── reports/                       # Generated reports output
└── tests/                         # Framework unit tests
```

## Flow Diagram

```
                    ┌─────────────────┐
                    │   User Input    │
                    │  (API / URL)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   CLI / Config  │
                    │   Parse Targets │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  API Scanner    │          │  URL Scanner    │
     │  (APITarget)    │          │  (URLTarget)    │
     └────────┬────────┘          └────────┬────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                    ┌────────▼────────┐
                    │  Security       │
                    │  Modules        │
                    │  (Pluggable)    │
                    ├─────────────────┤
                    │ • SQL Injection │
                    │ • XSS           │
                    │ • CSRF          │
                    │ • Headers       │
                    │ • CORS          │
                    │ • Info Leak     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  Test Generator │          │  Report Gen     │
     │  (pytest files) │          │  (JSON / HTML)  │
     └────────┬────────┘          └────────┬────────┘
              │                             │
     ┌────────▼────────┐          ┌────────▼────────┐
     │  test_cases/    │          │  reports/       │
     │  (decoupled)    │          │  (output)       │
     └─────────────────┘          └─────────────────┘
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Scan a single URL

```bash
python -m whitehats.cli scan --url https://example.com
```

### 2. Scan an API endpoint

```bash
python -m whitehats.cli scan --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

### 3. Scan API with POST body and auth token

```bash
python -m whitehats.cli scan \
  --url https://example.com/api/login \
  --api \
  --method POST \
  --body '{"username": "test", "password": "test123"}' \
  --token "your-bearer-token"
```

### 4. Scan multiple targets from file

```bash
python -m whitehats.cli scan --targets-file config/targets_example.json
```

### 5. Generate test cases only (no scanning)

```bash
python -m whitehats.cli generate --url https://example.com/api/users --api --method GET --params '{"id": "1"}'
```

Then run the generated tests:

```bash
pytest test_cases/
```

### 6. Use custom config

```bash
python -m whitehats.cli scan --url https://example.com -c my_config.yaml
```

## Security Modules

| Module | Description | Severity |
|--------|-------------|----------|
| SQL Injection | Tests params and body for SQL injection | HIGH |
| XSS | Tests for reflected cross-site scripting | HIGH |
| CSRF | Checks CSRF token and SameSite cookie | MEDIUM |
| Header Security | Audits security headers (HSTS, CSP, etc.) | MEDIUM |
| CORS Misconfig | Tests for CORS wildcard, reflection, null | MEDIUM |
| Info Disclosure | Scans for leaked sensitive data patterns | varies |

## Adding a Custom Module

Create a new file in `whitehats/modules/` inheriting from `BaseModule`:

```python
from whitehats.modules.base_module import BaseModule
from whitehats.models.vulnerability import Vulnerability, Severity

class MyCustomModule(BaseModule):
    name = "my_custom"
    description = "My custom security check"

    def run(self, target, baseline_response):
        findings = []
        # Your security test logic here
        return findings
```

Then add it to `whitehats/modules/__init__.py` in the `ALL_MODULES` list.

## Targets File Format

```json
{
  "targets": [
    {
      "type": "api",
      "url": "https://example.com/api/endpoint",
      "method": "POST",
      "params": {},
      "headers": {"Content-Type": "application/json"},
      "body": {"key": "value"},
      "auth_token": "optional-token"
    },
    {
      "type": "url",
      "url": "https://example.com/page"
    }
  ]
}
```
