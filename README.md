# OpenGuard

**OpenGuard** is a lightweight, zero-dependency C++17 security proxy for **Model Context Protocol (MCP)** stdio servers. It wraps any MCP child server process and inspects newline-delimited JSON-RPC 2.0 `tools/call` frames in real time before they reach the underlying tool runtime.

OpenGuard operates 100% locally with **strictly zero external network telemetry**.

---

## Features

- **Transparent Stdio Proxy**: Wraps any MCP server command via `openguard -- <child_command> [args...]` with bidirectionally piped `stdin`/`stdout`.
- **Deterministic `tools/call` Interception**: Inspects incoming JSON-RPC `tools/call` payloads while passing non-invocation messages (`initialize`, `tools/list`, notifications) through untouched.
- **Built-in Deterministic Block List**:
  - **Sensitive Credential Paths**: Blocks access to `~/.ssh`, `id_rsa`, `id_ed25519`, `.env`, `.aws/credentials`, `.config/gcloud`, `/etc/shadow`, `/etc/passwd`, and relative path traversal escapes (`../`).
  - **Destructive Shell Commands**: Halts `rm -rf /` (`--no-preserve-root`), fork bombs (`:(){ :|:& };:`), and remote script execution via shell pipes (`curl ... | bash`, `wget ... | sh`).
- **Standard JSON-RPC Error Synthesis**: Denied requests immediately return a JSON-RPC `-32602` error frame (`[OpenGuard] Denied: ...`) with the matching request `id` directly to the client without invoking or notifying the child process.
- **Local-Only Audit Logging**: Every blocked invocation is appended as a structured JSON line to `openguard_audit.log` (or a custom path via `--audit-log`).

---

## Project Structure

```text
openguard/
├── CMakeLists.txt
├── LICENSE                  # Apache-2.0
├── README.md
├── include/
│   └── openguard.hpp        # Policy engine, audit logger, and stdio proxy interfaces
└── src/
    ├── main.cpp             # CLI entrypoint
    └── proxy.cpp            # JSON-RPC inspector, deterministic rules, and process pipes
```

---

## Build & Quick Start

### Prerequisites

- CMake 3.14+
- A C++17 compatible compiler (`g++`, `clang++`, or MSVC)

### Build

```bash
mkdir build && cd build
cmake .. && cmake --build .
```

### Example: Blocking Sensitive SSH Key Reads

```bash
# Test blocking an attempt to read ~/.ssh/id_rsa
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/.ssh/id_rsa"}},"id":1}' | ./openguard -- cat
```

**Output (`stdout`):**

```json
{"jsonrpc":"2.0","error":{"code":-32602,"message":"[OpenGuard] Denied: Access to sensitive credential path blocked: SSH directory (~/.ssh) (/home/user/.ssh/id_rsa)"},"id":1}
```

**Audit Log (`openguard_audit.log`):**

```json
{"timestamp":"2026-11-05T05:18:00Z","action":"DENIED","category":"SENSITIVE_PATH","tool":"read_file","pattern":"/.ssh/","id":1,"reason":"Access to sensitive credential path blocked: SSH directory (~/.ssh) (/home/user/.ssh/id_rsa)","raw_request":"{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/home/user/.ssh/id_rsa\"}},\"id\":1}"}
```

### Example: Permitting Safe Tool Calls

```bash
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/project/README.md"}},"id":2}' | ./openguard -- cat
```

**Output (`stdout` forwarded through `cat`):**

```json
{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/project/README.md"}},"id":2}
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

