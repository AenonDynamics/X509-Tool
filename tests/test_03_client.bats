#!/usr/bin/env bats
# Tests for Client certificate operations: client add, client revoke

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- client add ---

@test "client add creates all files" {
    run x509 client add alice
    assert_success
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.key"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.csr"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12"
}

@test "client add cert not empty" {
    run x509 client add alice
    assert_success
    assert_file_not_empty "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_file_not_empty "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.key"
    assert_file_not_empty "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12"
}

@test "client add uses common name template" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -subject 2>/dev/null | grep -q "TESTCLIENT_alice"
}

@test "client add has clientauth eku" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -text 2>/dev/null | grep -q "TLS Web Client Authentication"
}

@test "client add has digital signature ku" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -text 2>/dev/null | grep -q "Digital Signature"
}

@test "client add has ca false" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -text 2>/dev/null | grep -q "CA:FALSE"
}

@test "client add is signed by ca" {
    run x509 client add alice
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" 2>&1 | grep -q "OK"
}

@test "client add p12 contains cert and key" {
    run x509 client add alice
    assert_success
    openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -nokeys -clcerts 2>/dev/null | grep -q "BEGIN CERTIFICATE"
}

@test "client add p12 contains ca chain" {
    run x509 client add alice
    assert_success
    local ca_count
    ca_count=$(openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -cacerts -nokeys 2>/dev/null | grep -c "BEGIN CERTIFICATE")
    [ "${ca_count}" -ge 1 ]
}

@test "client add multiple clients" {
    run x509 client add alice
    assert_success
    run x509 client add bob
    assert_success
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_bob/client.crt"
}

@test "client add output contains info" {
    run x509 client add alice
    assert_success
    assert_output_contains "creating certificate"
}

@test "client add creates unique serials" {
    run x509 client add alice
    assert_success
    run x509 client add bob
    assert_success
    local serial_a serial_b
    serial_a=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -serial 2>/dev/null)
    serial_b=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_bob/client.crt" -noout -serial 2>/dev/null)
    [ "${serial_a}" != "${serial_b}" ]
}

# --- client revoke ---

@test "client revoke succeeds" {
    run x509 client add alice
    assert_success
    run x509 client revoke alice
    assert_success
}

@test "client revoke updates crl" {
    run x509 client add alice
    assert_success
    local before
    before=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${before}" ] && before=0
    run x509 client revoke alice
    assert_success
    local after
    after=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${after}" ] && after=0
    [ "${after}" -gt "${before}" ]
}

@test "client revoke cert fails verification" {
    run x509 client add alice
    assert_success
    run x509 client revoke alice
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt' 2>&1"
    assert_failure
}

@test "client revoke nonexistent fails" {
    run x509 client revoke ghost
    assert_failure
}

@test "client revoke output contains revoking" {
    run x509 client add alice
    assert_success
    run x509 client revoke alice
    assert_success
    assert_output_contains "revoking cert"
}
