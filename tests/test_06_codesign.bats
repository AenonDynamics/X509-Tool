#!/usr/bin/env bats
# Tests for Code-Signing certificate operations: code add, code revoke
# Note: CRT_FILENAME for codesigning is "code" (not "sign")

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- code add ---

@test "code add creates all files" {
    run x509 code add mysigner
    assert_success
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt"
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.key"
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.csr"
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.p12"
}

@test "code add uses common name template" {
    run x509 code add mysigner
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" -noout -subject 2>/dev/null | grep -q "TESTCODE_mysigner"
}

@test "code add has codesigning eku" {
    run x509 code add mysigner
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" -noout -text 2>/dev/null | grep -qi "Code Signing"
}

@test "code add has clientauth eku" {
    run x509 code add mysigner
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" -noout -text 2>/dev/null | grep -q "TLS Web Client Authentication"
}

@test "code add has ca false" {
    run x509 code add mysigner
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" -noout -text 2>/dev/null | grep -q "CA:FALSE"
}

@test "code add is signed by ca" {
    run x509 code add mysigner
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" 2>&1 | grep -q "OK"
}

@test "code add cert not empty" {
    run x509 code add mysigner
    assert_success
    assert_file_not_empty "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt"
    assert_file_not_empty "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.p12"
}

# --- code revoke ---

@test "code revoke succeeds" {
    run x509 code add mysigner
    assert_success
    run x509 code revoke mysigner
    assert_success
}

@test "code revoke cert fails verification" {
    run x509 code add mysigner
    assert_success
    run x509 code revoke mysigner
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt' 2>&1"
    assert_failure
}

@test "code revoke nonexistent fails" {
    run x509 code revoke ghost
    assert_failure
}

@test "code revoke output contains revoking" {
    run x509 code add mysigner
    assert_success
    run x509 code revoke mysigner
    assert_success
    assert_output_contains "revoking cert"
}
