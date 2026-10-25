#!/usr/bin/env bats
# Tests for CA initialization: ca init

load helpers

setup() {
    setup_test_workdir
}

teardown() {
    cleanup_test_workdir
}

@test "ca init creates directory structure" {
    run x509 ca init MyCA
    assert_success
    assert_dir_exists "${TEST_WORKDIR}/ca"
    assert_dir_exists "${TEST_WORKDIR}/ica"
    assert_dir_exists "${TEST_WORKDIR}/server"
    assert_dir_exists "${TEST_WORKDIR}/client"
    assert_dir_exists "${TEST_WORKDIR}/host"
    assert_dir_exists "${TEST_WORKDIR}/codesign"
    assert_dir_exists "${TEST_WORKDIR}/smime"
}

@test "ca init creates ca cert and key" {
    run x509 ca init MyCA
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ca/ca.crt"
    assert_file_exists "${TEST_WORKDIR}/ca/ca.key"
    assert_file_not_empty "${TEST_WORKDIR}/ca/ca.crt"
    assert_file_not_empty "${TEST_WORKDIR}/ca/ca.key"
}

@test "ca init creates database files" {
    run x509 ca init MyCA
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ca/db.txt"
    assert_file_exists "${TEST_WORKDIR}/ca/db.txt.attr"
    assert_file_exists "${TEST_WORKDIR}/ca/serial"
}

@test "ca init creates crl" {
    run x509 ca init MyCA
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ca/crl.pem"
    assert_file_not_empty "${TEST_WORKDIR}/ca/crl.pem"
    assert_file_exists "${TEST_WORKDIR}/ca/ca-crl-verify.pem"
}

@test "ca init creates fullchain" {
    run x509 ca init MyCA
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ca/ca-fullchain.pem"
    assert_file_not_empty "${TEST_WORKDIR}/ca/ca-fullchain.pem"
}

@test "ca init uses common name template" {
    run x509 ca init MyCA
    assert_success
    # CA_COMMON_NAME="TESTCA_%s" -> TESTCA_MyCA
    openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -subject 2>/dev/null | grep -q "TESTCA_MyCA"
}

@test "ca init ca cert is self signed" {
    run x509 ca init MyCA
    assert_success
    local issuer subject
    issuer=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -issuer 2>/dev/null)
    subject=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -subject 2>/dev/null)
    assert_equal "${issuer#issuer=}" "${subject#subject=}"
}

@test "ca init ca cert has ca true" {
    run x509 ca init MyCA
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -text 2>/dev/null | grep -q "CA:TRUE"
}

@test "ca init ca cert has keycertsign" {
    run x509 ca init MyCA
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -text 2>/dev/null | grep -q "Certificate Sign"
}

@test "ca init output contains ca info" {
    run x509 ca init MyCA
    assert_success
    assert_output_contains "Initializing CA"
}

@test "ca init twice fails" {
    run x509 ca init MyCA
    assert_success
    run x509 ca init MyCA
    assert_failure
    assert_output_contains "already exists"
}

@test "ca init different names fails in same dir" {
    run x509 ca init CA1
    assert_success
    # Second init in same dir should fail (dir already exists)
    run x509 ca init CA2
    assert_failure
}
