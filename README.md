# Python Log Analyzer

A lightweight **Python CLI tool** for analyzing Linux SSH authentication logs and detecting suspicious login activity such as brute-force attempts and targeted accounts.

This project demonstrates practical cybersecurity skills including **log analysis, Python automation, regex parsing, and defensive security monitoring**.

---

## Overview

Security teams frequently analyze authentication logs to detect suspicious activity. This tool parses SSH authentication logs and identifies patterns that may indicate brute-force attacks or unauthorized login attempts.

The analyzer extracts useful security insights such as:

* Failed login attempts
* Suspicious IP addresses
* Targeted usernames
* Successful logins following repeated failures

---

## Features

* Detects failed SSH login attempts
* Counts failed attempts by IP address
* Tracks usernames targeted by attackers
* Flags suspicious IPs above a configurable threshold
* Detects successful logins that occur after prior failures
* Optional JSON export for structured analysis

---

## Project Structure

```
python-log-analyzer/
│
├── src/
│   └── log_analyzer.py        # Main log analysis script
│
├── sample_logs/
│   └── auth_sample.log        # Example SSH authentication log
│
├── output/                    # Optional JSON output directory
│
├── README.md
├── LICENSE
└── .gitignore
```

---

## Installation

Clone the repository:

```
git clone https://github.com/YOUR-USERNAME/python-log-analyzer.git
cd python-log-analyzer
```

(Optional) create a virtual environment:

```
python -m venv .venv
source .venv/bin/activate
```

No external dependencies are required.

---

## Usage

Run the log analyzer:

```
python src/log_analyzer.py -f sample_logs/auth_sample.log
```

Run with a custom suspicious-IP threshold:

```
python src/log_analyzer.py -f sample_logs/auth_sample.log -t 3
```

Export results to JSON:

```
python src/log_analyzer.py -f sample_logs/auth_sample.log -o output/results.json
```

---

## Example Output

```
=== Authentication Log Analysis Report ===
Log file: sample_logs/auth_sample.log
Total failed attempts: 6
Total successful logins: 2

Top failed IPs:
192.168.1.50 — 5 failed attempts

Top targeted usernames:
root — 3 attempts
admin — 2 attempts

Suspicious IPs:
192.168.1.50 — flagged for brute force behavior
```

---

## Why This Project Matters

Log analysis is a fundamental skill used in:

* Security Operations Centers (SOC)
* Incident response investigations
* Threat hunting
* Defensive monitoring
* Security automation

This project demonstrates:

* Python scripting
* Regular expression log parsing
* CLI tool development
* Security-focused data analysis
* Professional project documentation

---

## Ethical Use

This tool is intended for:

* educational use
* cybersecurity labs
* defensive log analysis
* authorized environments

Do **not** analyze logs from systems you do not own or have permission to access.

---

## Future Improvements

Possible enhancements for this project:

* Support additional log formats (Apache / Nginx / Windows logs)
* Add CSV export functionality
* Detect time-based brute force attacks
* Build a visualization dashboard
* Add automated unit tests
* Package the tool as a pip-installable CLI

---

## License

This project is licensed under the **MIT License**.
