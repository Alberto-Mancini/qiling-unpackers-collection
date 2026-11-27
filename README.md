# Qiling Malware Harnesses Collection

## Mission
This repository contains a collection of targeted in-memory unpackers and Indicator of Compromise (IoC) extractors built using the [Qiling](https://qiling.io/) framework. 

The primary goal of these harnesses is to achieve rapid, targeted emulation to bypass sophisticated anti-VM/anti-analysis techniques and avoid the overhead and risks associated with full sandbox execution. By hooking specific API calls and controlling the execution flow, we can surgically extract payloads and configuration data in-memory before malicious actions (like process injection or network beaconing) are allowed to proceed.

## Analyzed Malware Index

| Malware Family | Harness Goal | Module Link |
| --- | --- | --- |
| PlugX | Stage-1 In-Memory Unpacker (LZNT1) | [plugx/](./plugx) |

## AI Assistance

This study was assisted by **Antigravity** (powered by the **Gemini 4 Carbon** model), an AI agent used to monitor, review, and refine the codebase for consistency, portability, and reproducibility while preserving the original analysis logic.
