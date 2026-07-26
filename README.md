# Malware Reverse Engineering with Qiling

This repository contains Python scripts utilized for reverse engineering malware using the [Qiling Framework](https://qiling.io/). The scripts are developed as part of an internship project focused on malware analysis, emulation, and evasion techniques.

## ⚠️ Security Warning

**DO NOT** run any actual malware samples outside of a properly isolated, secure sandbox environment. The scripts provided here are intended for educational and professional malware analysis purposes only. 

- Ensure you are working in an isolated Virtual Machine (VM).
- Never execute unknown binaries on your host system.
- Use at your own risk.

## Contents

- `PlugX.py`: A Qiling emulation script designed to analyze malware behavior, specifically targeting anti-debugging and anti-sandboxing techniques used by variants such as PlugX. It includes API hooking for functions like `LoadLibraryA/W`, `CreateFileA/W`, `GetTickCount`, `Sleep`, and `GetCursorPos` to observe and bypass evasion mechanisms.

## Prerequisites

- Python 3.x
- Qiling Framework

Install the necessary dependencies using `pip`:

```bash
pip install qiling
```

## Usage

To use the emulation script with a malware sample, you generally run it as follows (assuming proper Qiling setup and rootfs):

```bash
python PlugX.py <path_to_malware_sample>
```

*(Note: Always refer to the specific script's internal comments for detailed configuration and rootfs setup instructions.)*

## Corporate and Security Best Practices

- **Zero Trust**: Treat all analyzed files as malicious.
- **Data Handling**: Do not upload proprietary or confidential malware samples to public repositories.
- **Commit Hygiene**: Ensure no sensitive data, API keys, or personal information is committed to the version history.
