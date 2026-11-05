// Copyright 2026 OpenGuard Contributors
// SPDX-License-Identifier: Apache-2.0

#include "openguard.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [--audit-log <file>] -- <child_command> [args...]\n\n"
        << "OpenGuard: Deterministic MCP JSON-RPC Stdio Security Proxy\n\n"
        << "Options:\n"
        << "  --audit-log <file>   Path to local audit log (default: openguard_audit.log)\n"
        << "  -h, --help           Show this help message and exit\n"
        << "  -v, --version        Show version information and exit\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    openguard::ProxyConfig config;

    int i = 1;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            ++i;
            break;
        }
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "-v" || arg == "--version") {
            std::cout << "openguard 0.1.0\n";
            return 0;
        }
        if (arg == "--audit-log") {
            if (i + 1 >= argc) {
                std::cerr << "[OpenGuard] Error: --audit-log requires a file path.\n";
                print_usage(argv[0]);
                return 1;
            }
            config.audit_log_path = argv[++i];
            continue;
        }
        // If a non-flag argument appears without `--`, treat it as the start of child_argv
        if (!arg.empty() && arg[0] != '-') {
            break;
        }
        std::cerr << "[OpenGuard] Error: Unknown option '" << arg << "'.\n";
        print_usage(argv[0]);
        return 1;
    }

    for (; i < argc; ++i) {
        config.child_argv.emplace_back(argv[i]);
    }

    if (config.child_argv.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    openguard::ProxyRunner runner(std::move(config));
    return runner.run();
}

