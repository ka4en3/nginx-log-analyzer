# Nginx Log Analyzer
Nginx log analyzer to identify problematic URLs with high processing time.
## Features
- Parsing nginx logs in ui_short format
- Support for compressed (gzip) and regular logs
- Calculating statistics by URL (count, time_sum, time_avg, time_max, time_med)
- Generating HTML reports with sortable tables
- Structured logging in JSON format
- Checking the parsing error threshold
- Skipping already processed logs
## Installation
### Requirements
- Python 3.10+
- UV package manager
### Install with UV
```bash
# clone repository
git clone https://github.com/ka4en3/nginx-log-analyzer.git
cd nginx-log-analyzer

# create virtual environment
uv venv
source .venv/bin/activate
# or
.venv\\Scripts\\activate  # Windows

# install dependencies
uv pip install -e ".[dev]"
# or
make install
```

## How to use
### Basic usage
```bash
# analyze latest log
python -m log_analyzer

# set custom config
python -m log_analyzer --config /path/to/config.json
```

## Configuration
### Create config file:
``` json
{
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./logs",
    "LOG_FILE": null,
    "ERROR_THRESHOLD": 0.1
}
```

### Parameters
- REPORT_SIZE - number of URLs in the report
- REPORT_DIR - directory for saving reports
- LOG_DIR - directory with nginx logs
- LOG_FILE - path to the file for logging (null - output to stdout)
- ERROR_THRESHOLD - maximum percentage of parsing errors (0.1 = 10%)

## Log format
### Expected log format (ui_short):
``` json
$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" $request_time
```

### Log file names must match the pattern:

- nginx-access-ui.log-YYYYMMDD
- nginx-access-ui.log-YYYYMMDD.gz

## Development
### Run tests
```bash
# Makefile
make test
# or
python -m pytest
```

### Check code coverage
```bash
# Makefile
make coverage
# or
python -m pytest --cov=src/log_analyzer --cov-report=html
```

### Check code style
```bash
# linter
make lint
# formatter
make format
# type-check
make type-check
```

### Pre-commit hooks
```bash
# install hooks
pre-commit install
# or
make install
# run hooks
pre-commit run --all-files
```

## Project structure
```json
nginx-log-analyzer/
├── src/
│   └── log_analyzer/
│       ├── __init__.py
│       ├── __main__.py
│       └── log_analyzer.py
├── tests/
│   └── test_log_analyzer.py
├── templates/
│   └── report.html
├── logs/
├── reports/
├── config.json
├── pyproject.toml
├── README.md
└── Makefile
```

## Report example
### The report is generated in HTML format with a table containing:
- URL
- Count - number of requests
- Count % - percentage of total requests
- Time Sum - total processing time
- Time % - percentage of total time
- Time Avg - average processing time
- Time Max - maximum processing time
- Time Med - median processing time

## License
MIT
