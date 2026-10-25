#!/usr/bin/env bats
# ----------------------------------------------------------------------
# Tests for: x509-tool util genpkey <output-file>
# Verifies all openssl passphrase options for RSA and EC private keys:
#   - pass:<password>   static password
#   - pass:             empty static password
#   - file:<path>       password read from file (first line)
#   - env:<VAR>         password read from environment variable
#
# References:
#   https://docs.openssl.org/3.6/man1/openssl-passphrase-options
# ----------------------------------------------------------------------

load helpers

setup() {
    setup_test_workdir
}

teardown() {
    cleanup_test_workdir
}

# ======================================================================
# Helper functions
# ======================================================================

# Configure cert.conf for a specific key type and PKEY_PASS_TYPE
configure_genpkey() {
    local key_type="$1"
    local pass_type="$2"
    sed -i "s/export KEY_TYPE=\".*\"/export KEY_TYPE=\"${key_type}\"/" "${TEST_WORKDIR}/cert.conf"
    sed -i "s#PKEY_PASS_TYPE=\".*\"#PKEY_PASS_TYPE=\"${pass_type}\"#" "${TEST_WORKDIR}/cert.conf"
}

# Assert key can be decrypted with the given passin argument
assert_key_readable() {
    local key_file="$1"
    local passin="$2"
    openssl pkey -in "${key_file}" -passin "${passin}" -noout 2>/dev/null
}

# Assert key CANNOT be decrypted with the given passin argument
assert_key_not_readable() {
    local key_file="$1"
    local passin="$2"
    ! openssl pkey -in "${key_file}" -passin "${passin}" -noout 2>/dev/null
}

# Assert key algorithm matches expected (EC 256-bit or RSA 2048-bit)
assert_key_type() {
    local key_file="$1"
    local passin="$2"
    local expected="$3"
    openssl pkey -in "${key_file}" -passin "${passin}" -noout -text 2>/dev/null | head -1 | grep -q "${expected}"
}

# Assert key file is an encrypted PEM (not plaintext)
assert_key_is_encrypted() {
    local key_file="$1"
    head -1 "${key_file}" | grep -q "ENCRYPTED PRIVATE KEY"
}

# ======================================================================
# EC Key — static password (pass:<secret>)
# ======================================================================

@test "genpkey EC with static password (pass:secret)" {
    configure_genpkey "EC" "pass:secret123"
    run x509 util genpkey ec-static.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ec-static.key"
    assert_file_not_empty "${TEST_WORKDIR}/ec-static.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/ec-static.key"
    assert_key_readable "${TEST_WORKDIR}/ec-static.key" "pass:secret123"
    assert_key_not_readable "${TEST_WORKDIR}/ec-static.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/ec-static.key" "pass:secret123" "Private-Key.*256 bit"
}

# ======================================================================
# EC Key — empty static password (pass:)
# ======================================================================

@test "genpkey EC with empty static password (pass:)" {
    configure_genpkey "EC" "pass:"
    run x509 util genpkey ec-empty.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ec-empty.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/ec-empty.key"
    assert_key_readable "${TEST_WORKDIR}/ec-empty.key" "pass:"
    assert_key_not_readable "${TEST_WORKDIR}/ec-empty.key" "pass:something"
    assert_key_type "${TEST_WORKDIR}/ec-empty.key" "pass:" "Private-Key.*256 bit"
}

# ======================================================================
# EC Key — password from file (file:<path>)
# ======================================================================

@test "genpkey EC with password from file (file:)" {
    echo "filepass456" > "${TEST_WORKDIR}/keypass.txt"
    configure_genpkey "EC" "file:${TEST_WORKDIR}/keypass.txt"
    run x509 util genpkey ec-file.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ec-file.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/ec-file.key"
    assert_key_readable "${TEST_WORKDIR}/ec-file.key" "pass:filepass456"
    assert_key_not_readable "${TEST_WORKDIR}/ec-file.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/ec-file.key" "pass:filepass456" "Private-Key.*256 bit"
}

# ======================================================================
# EC Key — password from environment variable (env:<VAR>)
# ======================================================================

@test "genpkey EC with password from env (env:)" {
    export X509_TEST_PW="envpass789"
    configure_genpkey "EC" "env:X509_TEST_PW"
    run x509 util genpkey ec-env.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ec-env.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/ec-env.key"
    assert_key_readable "${TEST_WORKDIR}/ec-env.key" "pass:envpass789"
    assert_key_not_readable "${TEST_WORKDIR}/ec-env.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/ec-env.key" "pass:envpass789" "Private-Key.*256 bit"
}

# ======================================================================
# RSA Key — static password (pass:<secret>)
# ======================================================================

@test "genpkey RSA with static password (pass:secret)" {
    configure_genpkey "RSA" "pass:secret123"
    run x509 util genpkey rsa-static.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/rsa-static.key"
    assert_file_not_empty "${TEST_WORKDIR}/rsa-static.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/rsa-static.key"
    assert_key_readable "${TEST_WORKDIR}/rsa-static.key" "pass:secret123"
    assert_key_not_readable "${TEST_WORKDIR}/rsa-static.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/rsa-static.key" "pass:secret123" "Private-Key.*2048 bit"
}

# ======================================================================
# RSA Key — empty static password (pass:)
# ======================================================================

@test "genpkey RSA with empty static password (pass:)" {
    configure_genpkey "RSA" "pass:"
    run x509 util genpkey rsa-empty.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/rsa-empty.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/rsa-empty.key"
    assert_key_readable "${TEST_WORKDIR}/rsa-empty.key" "pass:"
    assert_key_not_readable "${TEST_WORKDIR}/rsa-empty.key" "pass:something"
    assert_key_type "${TEST_WORKDIR}/rsa-empty.key" "pass:" "Private-Key.*2048 bit"
}

# ======================================================================
# RSA Key — password from file (file:<path>)
# ======================================================================

@test "genpkey RSA with password from file (file:)" {
    echo "filepass456" > "${TEST_WORKDIR}/keypass.txt"
    configure_genpkey "RSA" "file:${TEST_WORKDIR}/keypass.txt"
    run x509 util genpkey rsa-file.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/rsa-file.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/rsa-file.key"
    assert_key_readable "${TEST_WORKDIR}/rsa-file.key" "pass:filepass456"
    assert_key_not_readable "${TEST_WORKDIR}/rsa-file.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/rsa-file.key" "pass:filepass456" "Private-Key.*2048 bit"
}

# ======================================================================
# RSA Key — password from environment variable (env:<VAR>)
# ======================================================================

@test "genpkey RSA with password from env (env:)" {
    export X509_TEST_PW="envpass789"
    configure_genpkey "RSA" "env:X509_TEST_PW"
    run x509 util genpkey rsa-env.key
    assert_success
    assert_file_exists "${TEST_WORKDIR}/rsa-env.key"
    assert_key_is_encrypted "${TEST_WORKDIR}/rsa-env.key"
    assert_key_readable "${TEST_WORKDIR}/rsa-env.key" "pass:envpass789"
    assert_key_not_readable "${TEST_WORKDIR}/rsa-env.key" "pass:wrongpass"
    assert_key_type "${TEST_WORKDIR}/rsa-env.key" "pass:envpass789" "Private-Key.*2048 bit"
}

# ======================================================================
# Negative: missing output file argument
# ======================================================================

@test "genpkey without output file fails" {
    run x509 util genpkey
    assert_failure
    assert_output_contains "output file required"
}

# ======================================================================
# Negative: missing cert.conf
# ======================================================================

@test "genpkey without cert.conf fails" {
    rm "${TEST_WORKDIR}/cert.conf"
    run x509 util genpkey test.key
    assert_failure
    assert_output_contains "cert.conf not found"
}
