# OpenGuard

[![CI](https://github.com/openguard-project/openguard/actions/workflows/ci.yml/badge.svg)](https://github.com/openguard-project/openguard/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++17](https://img.shields.io/badge/Standard-C%2B%2B17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Architecture: Air-Gapped](https://img.shields.io/badge/Architecture-Air--Gapped-success.svg)](#)

> **Deterministic, zero-telemetry execution boundaries for local AI agents and MCP tools.**

OpenGuard is an open-source, sovereign security broker written in modern C++17. It intercepts bidirectional JSON-RPC 2.0 tool calls over standard I/O pipes between autonomous AI agents (Claude Code, Cursor, MCP runners) and local environments. OpenGuard enforces deterministic execution boundaries with sub-2ms latency—blocking credential harvesting, unconstrained file mutations, and unauthorized system access without sending any telemetry to the cloud.

---

## The Threat Model

Autonomous coding agents and AI CLI tools operate with ambient user credentials. A compromised package, poisoned prompt, or hallucinated command can lead to:
- **Credential exfiltration:** Reading `~/.ssh`, `~/.aws/credentials`, or repository `.env` files.
- **Silent data modification:** Destructive deletions or malicious supply-chain commits.
- **Uncontrolled process execution:** Spawning reverse shells or outbound network beacons.

Commercial solutions address this by routing developer telemetry and code snippets to proprietary remote firewalls. **OpenGuard solves this entirely on-device with zero external network dependencies.**

---

## Architecture

OpenGuard functions as a transparent, low-overhead pipe shim between the AI agent host and the target tool:

```text
┌──────────────────┐
│   Agent Client   │ (Claude Code, Cursor, MCP Runner)
└────────┬─────────┘
         │ Stdin / Stdout (JSON-RPC 2.0)
         ▼
┌──────────────────┐
│    OpenGuard     │ ◄── Sub-2ms Deterministic Policy Engine
│  (C++17 Broker)  │ ◄── Append-Only Tamper-Evident Audit Log
└────────┬─────────┘
         │ Filtered / Approved Stream
         ▼
┌──────────────────┐
│ Underlying Tool  │ (Bash, Filesystem MCP, System CLI)
└──────────────────┘