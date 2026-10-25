#!/usr/bin/env bats
# Tests for error handling and edge cases

load helpers

setup() {
    setup_test_workdir
}

teardown() {
    cleanup_test_workdir
}

# --- missing cert.conf ---

@test "missing cert.conf fails for ca init" {
    rm "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_failure
    assert_output_contains "cert.conf not found"
}

@test "missing cert.conf fails for client add" {
    rm "${TEST_WORKDIR}/cert.conf"
    run x509 client add alice
    assert_failure
    assert_output_contains "cert.conf not found"
}

# --- missing CA ---

@test "client add without ca fails" {
    run x509 client add alice
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "server add without ca fails" {
    run x509 server add web1
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "host add without ca fails" {
    run x509 host add node1
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "code add without ca fails" {
    run x509 code add signer
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "smime add without ca fails" {
    run x509 smime add alice alice@example.com
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "client revoke without ca fails" {
    run x509 client revoke alice
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

@test "verify without ca fails" {
    run x509 verify "/dev/null"
    assert_failure
    assert_output_contains "certificate authority doesn't exist"
}

# --- ICA without root CA ---

@test "ica init without root ca fails" {
    run x509 ica init SubCA IT
    assert_failure
}

# --- revoke non-existent certs ---

@test "revoke nonexistent client fails" {
    run x509 ca init TestCA
    assert_success
    run x509 client revoke ghost
    assert_failure
}

@test "revoke nonexistent server fails" {
    run x509 ca init TestCA
    assert_success
    run x509 server revoke ghost
    assert_failure
}

@test "revoke nonexistent host fails" {
    run x509 ca init TestCA
    assert_success
    run x509 host revoke ghost
    assert_failure
}

@test "revoke nonexistent code fails" {
    run x509 ca init TestCA
    assert_success
    run x509 code revoke ghost
    assert_failure
}

@test "revoke nonexistent smime fails" {
    run x509 ca init TestCA
    assert_success
    run x509 smime revoke ghost
    assert_failure
}

# --- show with missing file ---

@test "show missing file fails" {
    run x509 show "/nonexistent/path/cert.pem"
    assert_failure
}

# --- verify with missing file ---

@test "verify missing file fails" {
    run x509 ca init TestCA
    assert_success
    run x509 verify "/nonexistent/path/cert.pem"
    assert_failure
}

# --- smime add without email ---

@test "smime add without email fails" {
    run x509 ca init TestCA
    assert_success
    run x509 smime add alice
    assert_failure
}

# --- double CA init ---

@test "ca init twice in same dir fails" {
    run x509 ca init TestCA
    assert_success
    run x509 ca init TestCA
    assert_failure
    assert_output_contains "already exists"
}

# --- double ICA init ---

@test "ica init twice fails" {
    run x509 ca init TestCA
    assert_success
    run x509 ica init SubCA IT
    assert_success
    run x509 ica init SubCA IT
    assert_failure
    assert_output_contains "already exists"
}
