#!/usr/bin/env bats
# Tests for Host certificate operations: host add, host revoke (with/without SANs)

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- host add ---

@test "host add creates all files" {
    run x509 host add node1
    assert_success
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt"
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/host.key"
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/host.csr"
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/host.p12"
}

@test "host add uses common name template" {
    run x509 host add node1
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -subject 2>/dev/null | grep -q "TESTHOST_node1"
}

@test "host add has serverauth and clientauth eku" {
    run x509 host add node1
    assert_success
    local text
    text=$(openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -text 2>/dev/null)
    echo "${text}" | grep -q "TLS Web Server Authentication"
    echo "${text}" | grep -q "TLS Web Client Authentication"
}

@test "host add default san includes cn" {
    run x509 host add node1
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -text 2>/dev/null | grep -q "DNS:TESTHOST_node1"
}

@test "host add with sans" {
    run x509 host add node1 node1.lan node1.local
    assert_success
    local san
    san=$(openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name")
    echo "${san}" | grep -q "DNS:TESTHOST_node1"
    echo "${san}" | grep -q "DNS:node1.lan"
    echo "${san}" | grep -q "DNS:node1.local"
}

@test "host add has ca false" {
    run x509 host add node1
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -text 2>/dev/null | grep -q "CA:FALSE"
}

@test "host add is signed by ca" {
    run x509 host add node1
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" 2>&1 | grep -q "OK"
}

# --- host revoke ---

@test "host revoke succeeds" {
    run x509 host add node1
    assert_success
    run x509 host revoke node1
    assert_success
}

@test "host revoke cert fails verification" {
    run x509 host add node1
    assert_success
    run x509 host revoke node1
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/host/TESTHOST_node1/host.crt' 2>&1"
    assert_failure
}

@test "host revoke nonexistent fails" {
    run x509 host revoke ghost
    assert_failure
}
