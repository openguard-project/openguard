// Copyright 2026 OpenGuard Contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENGUARD_HPP
#define OPENGUARD_HPP

#include <string>
#include <vector>

namespace openguard {

/**
 * Result of evaluating an incoming JSON-RPC line against OpenGuard's
 * deterministic security policy.
 */
struct Verdict {
    bool allowed = true;
    std::string rule_category;
    std::string reason;
    std::string tool_name;
    std::string matched_pattern;
    std::string rpc_id_raw = "null";
};

/**
 * Configuration options for the OpenGuard stdio proxy.
 */
struct ProxyConfig {
    std::string audit_log_path = "openguard_audit.log";
    std::vector<std::string> child_argv;
};

/**
 * Deterministic, zero-dependency policy engine that inspects MCP JSON-RPC
 * `tools/call` frames for sensitive credential paths and destructive shell
 * invocations.
 */
class SecurityPolicy {
public:
    SecurityPolicy() = default;

    /**
     * Inspects a single newline-delimited JSON-RPC frame.
     * Non-`tools/call` messages are permitted unmodified.
     */
    Verdict evaluate_frame(const std::string& json_line) const;

    /**
     * Synthesizes a standard JSON-RPC 2.0 error response (-32602) for a
     * denied invocation without forwarding the frame to the child process.
     */
    static std::string build_error_response(const Verdict& verdict);
};

/**
 * Local-only append logger for security events.
 * Guarantees strictly zero external network telemetry.
 */
class AuditLogger {
public:
    explicit AuditLogger(std::string log_path);

    /**
     * Appends a single structured audit record to the local log file.
     */
    void log_denied(const Verdict& verdict, const std::string& raw_frame) const;

private:
    std::string log_path_;
};

/**
 * Bidirectional stdio wrapper that spawns the target MCP server process,
 * intercepts stdin frames through SecurityPolicy, and relays permitted
 * traffic between the host client and child server.
 */
class ProxyRunner {
public:
    explicit ProxyRunner(ProxyConfig config);

    /**
     * Launches the child process and runs the interception loop until EOF.
     * Returns the process exit status.
     */
    int run();

private:
    ProxyConfig config_;
    SecurityPolicy policy_;
    AuditLogger logger_;
};

}  // namespace openguard

#endif  // OPENGUARD_HPP

