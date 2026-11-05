// Copyright 2026 OpenGuard Contributors
// SPDX-License-Identifier: Apache-2.0

#include "openguard.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace openguard {
namespace {

std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (unsigned char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

std::string to_lower_copy(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Skips whitespace starting at pos
size_t skip_ws(const std::string& s, size_t pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
    return pos;
}

// Parses a JSON string literal starting at the opening quote at `pos`.
// Advances `pos` to one past the closing quote and returns the unescaped content.
bool parse_json_string(const std::string& s, size_t& pos, std::string& out) {
    if (pos >= s.size() || s[pos] != '"') {
        return false;
    }
    ++pos;
    out.clear();
    while (pos < s.size()) {
        char c = s[pos++];
        if (c == '"') {
            return true;
        }
        if (c == '\\' && pos < s.size()) {
            char esc = s[pos++];
            switch (esc) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                default:   out.push_back(esc);  break;
            }
        } else {
            out.push_back(c);
        }
    }
    return false;
}

// Extracts the raw JSON token (string, number, boolean, null, object, or array)
// starting at `pos` and advances `pos` past the token.
std::string extract_raw_json_value(const std::string& s, size_t& pos) {
    pos = skip_ws(s, pos);
    if (pos >= s.size()) {
        return "null";
    }
    size_t start = pos;
    if (s[pos] == '"') {
        ++pos;
        while (pos < s.size()) {
            if (s[pos] == '\\') {
                pos += 2;
                continue;
            }
            if (s[pos] == '"') {
                ++pos;
                break;
            }
            ++pos;
        }
        return s.substr(start, pos - start);
    }
    if (s[pos] == '{' || s[pos] == '[') {
        char open = s[pos];
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        bool in_str = false;
        while (pos < s.size()) {
            char c = s[pos];
            if (in_str) {
                if (c == '\\') {
                    pos += 2;
                    continue;
                }
                if (c == '"') {
                    in_str = false;
                }
            } else {
                if (c == '"') {
                    in_str = true;
                } else if (c == open) {
                    ++depth;
                } else if (c == close) {
                    --depth;
                    if (depth == 0) {
                        ++pos;
                        break;
                    }
                }
            }
            ++pos;
        }
        return s.substr(start, pos - start);
    }
    while (pos < s.size() &&
           !std::isspace(static_cast<unsigned char>(s[pos])) &&
           s[pos] != ',' && s[pos] != '}' && s[pos] != ']') {
        ++pos;
    }
    return s.substr(start, pos - start);
}

struct ParsedRpcCall {
    bool is_tools_call = false;
    std::string id_raw = "null";
    std::string tool_name;
    std::vector<std::string> argument_strings;
    std::string raw_arguments_block;
};

// Collects all string values inside a JSON value block (e.g. `arguments`).
void collect_json_strings(const std::string& block, std::vector<std::string>& out) {
    size_t i = 0;
    while (i < block.size()) {
        if (block[i] == '"') {
            std::string val;
            if (parse_json_string(block, i, val)) {
                size_t next = skip_ws(block, i);
                // Only record values, or record both keys and values inside arguments
                // (recording values is ideal; if not followed by ':', it is a value)
                if (next >= block.size() || block[next] != ':') {
                    out.push_back(val);
                }
            }
        } else {
            ++i;
        }
    }
}

ParsedRpcCall parse_rpc_frame(const std::string& line) {
    ParsedRpcCall result;
    std::string method;
    std::string params_block;

    int depth = 0;
    size_t i = 0;
    while (i < line.size()) {
        i = skip_ws(line, i);
        if (i >= line.size()) break;

        char c = line[i];
        if (c == '{') {
            ++depth;
            ++i;
            continue;
        }
        if (c == '}') {
            --depth;
            ++i;
            continue;
        }
        if (c == '"' && depth == 1) {
            std::string key;
            if (!parse_json_string(line, i, key)) break;
            i = skip_ws(line, i);
            if (i < line.size() && line[i] == ':') {
                ++i;
                i = skip_ws(line, i);
                if (key == "method") {
                    parse_json_string(line, i, method);
                } else if (key == "id") {
                    result.id_raw = extract_raw_json_value(line, i);
                } else if (key == "params") {
                    params_block = extract_raw_json_value(line, i);
                } else {
                    extract_raw_json_value(line, i);
                }
            }
            continue;
        }
        if (c == '"') {
            std::string dummy;
            parse_json_string(line, i, dummy);
            continue;
        }
        ++i;
    }

    if (method != "tools/call") {
        return result;
    }
    result.is_tools_call = true;

    // Parse top-level fields of `params_block` ("name" and "arguments")
    int pdepth = 0;
    size_t j = 0;
    while (j < params_block.size()) {
        j = skip_ws(params_block, j);
        if (j >= params_block.size()) break;

        char c = params_block[j];
        if (c == '{') {
            ++pdepth;
            ++j;
            continue;
        }
        if (c == '}') {
            --pdepth;
            ++j;
            continue;
        }
        if (c == '"' && pdepth == 1) {
            std::string pkey;
            if (!parse_json_string(params_block, j, pkey)) break;
            j = skip_ws(params_block, j);
            if (j < params_block.size() && params_block[j] == ':') {
                ++j;
                j = skip_ws(params_block, j);
                if (pkey == "name") {
                    parse_json_string(params_block, j, result.tool_name);
                } else if (pkey == "arguments") {
                    result.raw_arguments_block = extract_raw_json_value(params_block, j);
                } else {
                    extract_raw_json_value(params_block, j);
                }
            }
            continue;
        }
        if (c == '"') {
            std::string dummy;
            parse_json_string(params_block, j, dummy);
            continue;
        }
        ++j;
    }

    if (!result.raw_arguments_block.empty()) {
        collect_json_strings(result.raw_arguments_block, result.argument_strings);
    }
    return result;
}

bool contains_dotenv_reference(const std::string& lower_arg) {
    size_t pos = 0;
    while ((pos = lower_arg.find(".env", pos)) != std::string::npos) {
        bool valid_prefix = (pos == 0) ||
                            lower_arg[pos - 1] == '/' ||
                            lower_arg[pos - 1] == '\\' ||
                            std::isspace(static_cast<unsigned char>(lower_arg[pos - 1])) ||
                            lower_arg[pos - 1] == '"' ||
                            lower_arg[pos - 1] == '\'';
        size_t end = pos + 4;
        bool valid_suffix = (end == lower_arg.size()) ||
                            lower_arg[end] == '.' ||
                            lower_arg[end] == '/' ||
                            lower_arg[end] == '\\' ||
                            std::isspace(static_cast<unsigned char>(lower_arg[end])) ||
                            lower_arg[end] == '"' ||
                            lower_arg[end] == '\'';
        if (valid_prefix && valid_suffix) {
            return true;
        }
        pos += 4;
    }
    return false;
}

bool contains_relative_traversal(const std::string& arg) {
    if (arg == ".." ||
        arg.find("../") != std::string::npos ||
        arg.find("..\\") != std::string::npos ||
        arg.find("/..") != std::string::npos ||
        arg.find("\\..") != std::string::npos) {
        return true;
    }
    return false;
}

bool contains_destructive_rm(const std::string& lower_arg) {
    if (lower_arg.find("--no-preserve-root") != std::string::npos) {
        return true;
    }
    // Check for combinations like `rm -rf /`, `rm -fr /`, `rm -r -f /`, `rm -rf /*`
    const char* patterns[] = {
        "rm -rf /",
        "rm -fr /",
        "rm -r -f /",
        "rm -f -r /"
    };
    for (const char* pat : patterns) {
        size_t pos = lower_arg.find(pat);
        if (pos != std::string::npos) {
            bool prefix_ok = (pos == 0) ||
                             std::isspace(static_cast<unsigned char>(lower_arg[pos - 1])) ||
                             lower_arg[pos - 1] == ';' ||
                             lower_arg[pos - 1] == '&' ||
                             lower_arg[pos - 1] == '|';
            size_t after_slash = pos + std::strlen(pat);
            bool is_root_target = (after_slash == lower_arg.size()) ||
                                  lower_arg[after_slash] == '*' ||
                                  std::isspace(static_cast<unsigned char>(lower_arg[after_slash])) ||
                                  lower_arg[after_slash] == ';' ||
                                  lower_arg[after_slash] == '&' ||
                                  lower_arg[after_slash] == '|';
            if (prefix_ok && is_root_target) {
                return true;
            }
        }
    }
    return false;
}

bool contains_fork_bomb(const std::string& arg) {
    std::string compact;
    compact.reserve(arg.size());
    for (unsigned char c : arg) {
        if (!std::isspace(c)) {
            compact.push_back(static_cast<char>(c));
        }
    }
    return compact.find(":(){:|:&};:") != std::string::npos;
}

bool contains_pipe_to_shell(const std::string& lower_arg) {
    bool has_fetcher = (lower_arg.find("curl ") != std::string::npos ||
                        lower_arg.find("wget ") != std::string::npos);
    if (!has_fetcher) {
        return false;
    }
    size_t pipe_pos = lower_arg.find('|');
    while (pipe_pos != std::string::npos) {
        size_t after = skip_ws(lower_arg, pipe_pos + 1);
        // Optional `sudo ` before shell
        if (lower_arg.compare(after, 5, "sudo ") == 0) {
            after = skip_ws(lower_arg, after + 5);
        }
        const char* shells[] = {"bash", "sh", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash"};
        for (const char* sh : shells) {
            size_t len = std::strlen(sh);
            if (lower_arg.compare(after, len, sh) == 0) {
                size_t end = after + len;
                if (end == lower_arg.size() ||
                    std::isspace(static_cast<unsigned char>(lower_arg[end])) ||
                    lower_arg[end] == ';' ||
                    lower_arg[end] == '&' ||
                    lower_arg[end] == '|') {
                    return true;
                }
            }
        }
        pipe_pos = lower_arg.find('|', pipe_pos + 1);
    }
    return false;
}

std::string current_utc_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return std::string(buf);
}

}  // namespace

Verdict SecurityPolicy::evaluate_frame(const std::string& json_line) const {
    Verdict verdict;
    ParsedRpcCall call = parse_rpc_frame(json_line);
    if (!call.is_tools_call) {
        return verdict;
    }

    verdict.rpc_id_raw = call.id_raw;
    verdict.tool_name = call.tool_name;

    struct SensitiveRule {
        const char* pattern;
        const char* label;
    };

    static const SensitiveRule kCredentialRules[] = {
        {"~/.ssh",           "SSH directory (~/.ssh)"},
        {"/.ssh/",           "SSH directory (~/.ssh)"},
        {"\\.ssh\\",         "SSH directory (.ssh)"},
        {"/.ssh",            "SSH directory (~/.ssh)"},
        {"id_rsa",           "SSH private key (id_rsa)"},
        {"id_ed25519",       "SSH private key (id_ed25519)"},
        {".aws/credentials", "AWS credentials (.aws/credentials)"},
        {".aws\\credentials","AWS credentials (.aws/credentials)"},
        {".config/gcloud",   "Google Cloud credentials (.config/gcloud)"},
        {".config\\gcloud",  "Google Cloud credentials (.config/gcloud)"},
        {"/etc/shadow",      "System password hashes (/etc/shadow)"},
        {"/etc/passwd",      "System account database (/etc/passwd)"}
    };

    for (const std::string& arg : call.argument_strings) {
        std::string lower_arg = to_lower_copy(arg);

        // 1. Sensitive Credential Paths
        for (const auto& rule : kCredentialRules) {
            if (lower_arg.find(rule.pattern) != std::string::npos) {
                verdict.allowed = false;
                verdict.rule_category = "SENSITIVE_PATH";
                verdict.matched_pattern = rule.pattern;
                verdict.reason = std::string("Access to sensitive credential path blocked: ") +
                                 rule.label + " (" + arg + ")";
                return verdict;
            }
        }

        if (contains_dotenv_reference(lower_arg)) {
            verdict.allowed = false;
            verdict.rule_category = "SENSITIVE_PATH";
            verdict.matched_pattern = ".env";
            verdict.reason = "Access to environment secret file (.env) blocked (" + arg + ")";
            return verdict;
        }

        if (contains_relative_traversal(arg)) {
            verdict.allowed = false;
            verdict.rule_category = "PATH_TRAVERSAL";
            verdict.matched_pattern = "../";
            verdict.reason = "Relative path traversal escape (../) blocked (" + arg + ")";
            return verdict;
        }

        // 2. Destructive Shell Commands
        if (contains_destructive_rm(lower_arg)) {
            verdict.allowed = false;
            verdict.rule_category = "DESTRUCTIVE_COMMAND";
            verdict.matched_pattern = "rm -rf /";
            verdict.reason = "Destructive root filesystem deletion command blocked";
            return verdict;
        }

        if (contains_fork_bomb(arg)) {
            verdict.allowed = false;
            verdict.rule_category = "DESTRUCTIVE_COMMAND";
            verdict.matched_pattern = ":(){ :|:& };:";
            verdict.reason = "Fork bomb execution attempt blocked";
            return verdict;
        }

        if (contains_pipe_to_shell(lower_arg)) {
            verdict.allowed = false;
            verdict.rule_category = "DESTRUCTIVE_COMMAND";
            verdict.matched_pattern = "url_pipe_to_shell";
            verdict.reason = "Piping remote URL payload directly into a shell is blocked";
            return verdict;
        }
    }

    return verdict;
}

std::string SecurityPolicy::build_error_response(const Verdict& verdict) {
    std::ostringstream oss;
    oss << "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"[OpenGuard] Denied: "
        << json_escape(verdict.reason)
        << "\"},\"id\":" << (verdict.rpc_id_raw.empty() ? "null" : verdict.rpc_id_raw)
        << "}";
    return oss.str();
}

AuditLogger::AuditLogger(std::string log_path)
    : log_path_(std::move(log_path)) {}

void AuditLogger::log_denied(const Verdict& verdict, const std::string& raw_frame) const {
    std::ofstream out(log_path_, std::ios::app);
    if (!out.is_open()) {
        return;
    }
    out << "{\"timestamp\":\"" << current_utc_timestamp() << "\","
        << "\"action\":\"DENIED\","
        << "\"category\":\"" << json_escape(verdict.rule_category) << "\","
        << "\"tool\":\"" << json_escape(verdict.tool_name) << "\","
        << "\"pattern\":\"" << json_escape(verdict.matched_pattern) << "\","
        << "\"id\":" << (verdict.rpc_id_raw.empty() ? "null" : verdict.rpc_id_raw) << ","
        << "\"reason\":\"" << json_escape(verdict.reason) << "\","
        << "\"raw_request\":\"" << json_escape(raw_frame) << "\"}\n";
    out.flush();
}

ProxyRunner::ProxyRunner(ProxyConfig config)
    : config_(std::move(config)),
      policy_(),
      logger_(config_.audit_log_path) {}

#ifdef _WIN32

namespace {
std::string quote_win32_arg(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\n\v\"") == std::string::npos) {
        return arg;
    }
    std::string cmd = "\"";
    for (auto it = arg.begin();; ++it) {
        unsigned num_backslashes = 0;
        while (it != arg.end() && *it == '\\') {
            ++it;
            ++num_backslashes;
        }
        if (it == arg.end()) {
            cmd.append(num_backslashes * 2, '\\');
            break;
        } else if (*it == '"') {
            cmd.append(num_backslashes * 2 + 1, '\\');
            cmd.push_back(*it);
        } else {
            cmd.append(num_backslashes, '\\');
            cmd.push_back(*it);
        }
    }
    cmd.push_back('"');
    return cmd;
}
}  // namespace

int ProxyRunner::run() {
    if (config_.child_argv.empty()) {
        std::cerr << "[OpenGuard] Error: No child command specified.\n";
        return 1;
    }

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE child_stdin_rd = nullptr;
    HANDLE child_stdin_wr = nullptr;
    HANDLE child_stdout_rd = nullptr;
    HANDLE child_stdout_wr = nullptr;

    if (!CreatePipe(&child_stdin_rd, &child_stdin_wr, &sa, 0) ||
        !SetHandleInformation(child_stdin_wr, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "[OpenGuard] Error: Failed to create child stdin pipe.\n";
        return 1;
    }

    if (!CreatePipe(&child_stdout_rd, &child_stdout_wr, &sa, 0) ||
        !SetHandleInformation(child_stdout_rd, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(child_stdin_rd);
        CloseHandle(child_stdin_wr);
        std::cerr << "[OpenGuard] Error: Failed to create child stdout pipe.\n";
        return 1;
    }

    std::string cmdline;
    for (size_t i = 0; i < config_.child_argv.size(); ++i) {
        if (i > 0) cmdline.push_back(' ');
        cmdline += quote_win32_arg(config_.child_argv[i]);
    }

    STARTUPINFOA si{};
    si.cb = sizeof(STARTUPINFOA);
    si.hStdInput = child_stdin_rd;
    si.hStdOutput = child_stdout_wr;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi{};
    std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back('\0');

    BOOL spawned = CreateProcessA(
        nullptr,
        mutable_cmd.data(),
        nullptr,
        nullptr,
        TRUE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi);

    CloseHandle(child_stdin_rd);
    CloseHandle(child_stdout_wr);

    if (!spawned) {
        CloseHandle(child_stdin_wr);
        CloseHandle(child_stdout_rd);
        std::cerr << "[OpenGuard] Error: Failed to spawn child command: "
                  << config_.child_argv[0] << "\n";
        return 127;
    }

    std::mutex stdout_mutex;
    std::thread reader_thread([&]() {
        char buffer[4096];
        DWORD bytes_read = 0;
        while (ReadFile(child_stdout_rd, buffer, sizeof(buffer), &bytes_read, nullptr) &&
               bytes_read > 0) {
            std::lock_guard<std::mutex> lock(stdout_mutex);
            std::cout.write(buffer, static_cast<std::streamsize>(bytes_read));
            std::cout.flush();
        }
        CloseHandle(child_stdout_rd);
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        Verdict verdict = policy_.evaluate_frame(line);
        if (!verdict.allowed) {
            logger_.log_denied(verdict, line);
            std::string err_json = SecurityPolicy::build_error_response(verdict) + "\n";
            std::lock_guard<std::mutex> lock(stdout_mutex);
            std::cout.write(err_json.data(), static_cast<std::streamsize>(err_json.size()));
            std::cout.flush();
            continue;
        }
        std::string forwarded = line + "\n";
        DWORD written = 0;
        if (!WriteFile(child_stdin_wr, forwarded.data(),
                       static_cast<DWORD>(forwarded.size()), &written, nullptr)) {
            break;
        }
    }

    CloseHandle(child_stdin_wr);
    if (reader_thread.joinable()) {
        reader_thread.join();
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

#else

int ProxyRunner::run() {
    if (config_.child_argv.empty()) {
        std::cerr << "[OpenGuard] Error: No child command specified.\n";
        return 1;
    }

    int stdin_pipe[2];
    int stdout_pipe[2];

    if (pipe(stdin_pipe) != 0) {
        std::cerr << "[OpenGuard] Error: Failed to create child stdin pipe.\n";
        return 1;
    }
    if (pipe(stdout_pipe) != 0) {
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        std::cerr << "[OpenGuard] Error: Failed to create child stdout pipe.\n";
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        std::cerr << "[OpenGuard] Error: fork() failed.\n";
        return 1;
    }

    if (pid == 0) {
        // Child process: wire stdin and stdout to pipes
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);

        if (dup2(stdin_pipe[0], STDIN_FILENO) < 0 ||
            dup2(stdout_pipe[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);

        std::vector<char*> argv_ptrs;
        argv_ptrs.reserve(config_.child_argv.size() + 1);
        for (const std::string& arg : config_.child_argv) {
            argv_ptrs.push_back(const_cast<char*>(arg.c_str()));
        }
        argv_ptrs.push_back(nullptr);

        execvp(argv_ptrs[0], argv_ptrs.data());
        std::perror("[OpenGuard] execvp failed");
        _exit(127);
    }

    // Parent process
    close(stdin_pipe[0]);
    close(stdout_pipe[1]);

    std::mutex stdout_mutex;
    std::thread reader_thread([&]() {
        char buffer[4096];
        for (;;) {
            ssize_t n = read(stdout_pipe[0], buffer, sizeof(buffer));
            if (n > 0) {
                std::lock_guard<std::mutex> lock(stdout_mutex);
                std::cout.write(buffer, n);
                std::cout.flush();
            } else if (n == 0) {
                break;
            } else if (errno != EINTR) {
                break;
            }
        }
        close(stdout_pipe[0]);
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        Verdict verdict = policy_.evaluate_frame(line);
        if (!verdict.allowed) {
            logger_.log_denied(verdict, line);
            std::string err_json = SecurityPolicy::build_error_response(verdict) + "\n";
            std::lock_guard<std::mutex> lock(stdout_mutex);
            std::cout.write(err_json.data(), static_cast<std::streamsize>(err_json.size()));
            std::cout.flush();
            continue;
        }

        std::string forwarded = line + "\n";
        const char* ptr = forwarded.data();
        size_t remaining = forwarded.size();
        bool write_failed = false;
        while (remaining > 0) {
            ssize_t written = write(stdin_pipe[1], ptr, remaining);
            if (written > 0) {
                ptr += written;
                remaining -= static_cast<size_t>(written);
            } else if (written < 0 && errno == EINTR) {
                continue;
            } else {
                write_failed = true;
                break;
            }
        }
        if (write_failed) {
            break;
        }
    }

    close(stdin_pipe[1]);
    if (reader_thread.joinable()) {
        reader_thread.join();
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}

#endif

}  // namespace openguard

