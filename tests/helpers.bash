#!/usr/bin/env bash
# ----------------------------------------------------------------------
# bats helper library for x509-tool tests
# Loaded via: load helpers
# ----------------------------------------------------------------------

# Resolve paths relative to this file
HELPERS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TEST_FIXTURES_DIR="${HELPERS_DIR}/fixtures"
export TOOL_DIR="$(cd "${HELPERS_DIR}/.." && pwd)"

# ----------------------------------------------------------------------
# x509 <args...> — run x509-tool in TEST_WORKDIR with proper env
# Designed to be used with bats' `run`:
#   run x509 ca init TestCA
# ----------------------------------------------------------------------
x509() {
    (
        cd "${TEST_WORKDIR}" || exit 99
        CONF_DIR="${TOOL_DIR}" \
        LIB_DIR="${TOOL_DIR}/lib" \
        OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}" \
        OVPN_BIN="${OVPN_BIN:-/usr/sbin/openvpn}" \
        bash "${TOOL_DIR}/x509-tool" "$@"
    )
}

# ----------------------------------------------------------------------
# setup_test_workdir — create temp dir with cert.conf fixture
# Call from bats setup()
# ----------------------------------------------------------------------
setup_test_workdir() {
    TEST_WORKDIR="$(mktemp -d /tmp/x509-test-XXXXXX)"
    cp "${TEST_FIXTURES_DIR}/cert.conf" "${TEST_WORKDIR}/cert.conf"
}

# ----------------------------------------------------------------------
# cleanup_test_workdir — remove temp dir
# Call from bats teardown()
# ----------------------------------------------------------------------
cleanup_test_workdir() {
    [ -n "${TEST_WORKDIR:-}" ] && [ -d "${TEST_WORKDIR}" ] && rm -rf "${TEST_WORKDIR}"
    TEST_WORKDIR=""
}

# ----------------------------------------------------------------------
# Assertions — operate on bats' $status and $output
# ----------------------------------------------------------------------

assert_success() {
    if [ "$status" -ne 0 ]; then
        echo "ASSERTION FAILED: expected exit code 0, got ${status}" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_failure() {
    if [ "$status" -eq 0 ]; then
        echo "ASSERTION FAILED: expected non-zero exit code, got 0" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_exit_code() {
    local expected="$1"
    if [ "$status" -ne "$expected" ]; then
        echo "ASSERTION FAILED: expected exit code ${expected}, got ${status}" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_output_contains() {
    local needle="$1"
    if [[ "$output" != *"${needle}"* ]]; then
        echo "ASSERTION FAILED: output does not contain: '${needle}'" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_output_not_contains() {
    local needle="$1"
    if [[ "$output" == *"${needle}"* ]]; then
        echo "ASSERTION FAILED: output should not contain: '${needle}'" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_output_matches() {
    local pattern="$1"
    if ! [[ "$output" =~ ${pattern} ]]; then
        echo "ASSERTION FAILED: output does not match pattern: '${pattern}'" >&3
        echo "Output was:" >&3
        echo "$output" | head -20 | sed 's/^/  /' >&3
        return 1
    fi
}

assert_file_exists() {
    local path="$1"
    if [ ! -f "${path}" ]; then
        echo "ASSERTION FAILED: file does not exist: ${path}" >&3
        return 1
    fi
}

assert_file_not_exists() {
    local path="$1"
    if [ -f "${path}" ]; then
        echo "ASSERTION FAILED: file should not exist: ${path}" >&3
        return 1
    fi
}

assert_dir_exists() {
    local path="$1"
    if [ ! -d "${path}" ]; then
        echo "ASSERTION FAILED: directory does not exist: ${path}" >&3
        return 1
    fi
}

assert_dir_not_exists() {
    local path="$1"
    if [ -d "${path}" ]; then
        echo "ASSERTION FAILED: directory should not exist: ${path}" >&3
        return 1
    fi
}

assert_file_not_empty() {
    local path="$1"
    if [ ! -s "${path}" ]; then
        echo "ASSERTION FAILED: file is empty or missing: ${path}" >&3
        return 1
    fi
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    if [ "${expected}" != "${actual}" ]; then
        echo "ASSERTION FAILED: expected '${expected}', got '${actual}'" >&3
        return 1
    fi
}
