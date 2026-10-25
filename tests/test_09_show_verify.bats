#!/usr/bin/env bats
# Tests for show and verify commands

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
    run x509 client add alice
}

teardown() {
    cleanup_test_workdir
}

# --- show ---

@test "show displays cert text" {
    run x509 show "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "Certificate"
    assert_output_contains "Subject:"
    assert_output_contains "Issuer:"
}

@test "show displays common name" {
    run x509 show "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "TESTCLIENT_alice"
}

@test "show displays issuer" {
    run x509 show "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "TESTCA_TestCA"
}

@test "show displays validity" {
    run x509 show "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "Not Before"
    assert_output_contains "Not After"
}

@test "show displays key usage" {
    run x509 show "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "Key Usage"
}

@test "show nonexistent file fails" {
    run x509 show "/nonexistent/cert.pem"
    assert_failure
}

@test "show ca cert" {
    run x509 show "${TEST_WORKDIR}/ca/ca.crt"
    assert_success
    assert_output_contains "TESTCA_TestCA"
    assert_output_contains "CA:TRUE"
}

# --- verify ---

@test "verify valid cert succeeds" {
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "OK"
}

@test "verify output contains ok" {
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_matches ": OK"
}

@test "verify revoked cert fails" {
    run x509 client revoke alice
    assert_success
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_failure
}

@test "verify revoked cert shows error" {
    run x509 client revoke alice
    assert_success
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_failure
    assert_output_contains "certificate revoked"
}

@test "verify ca cert succeeds" {
    run x509 verify "${TEST_WORKDIR}/ca/ca.crt"
    assert_success
}

@test "verify nonexistent file fails" {
    run x509 verify "/nonexistent/cert.pem"
    assert_failure
}

@test "verify output contains verifying" {
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success
    assert_output_contains "Verifying Certificate"
}
