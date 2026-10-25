#!/usr/bin/env bats
# Tests for Intermediate CA: ica init

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

@test "ica init creates directory" {
    run x509 ica init SubCA IT
    assert_success
    assert_dir_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA"
}

@test "ica init creates ca structure" {
    run x509 ica init SubCA IT
    assert_success
    assert_dir_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca"
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt"
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.key"
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/db.txt"
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/serial"
}

@test "ica init creates fullchain" {
    run x509 ica init SubCA IT
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca-fullchain.pem"
    assert_file_not_empty "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca-fullchain.pem"
}

@test "ica init copies cert conf" {
    run x509 ica init SubCA IT
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/cert.conf"
}

@test "ica init uses common name template" {
    run x509 ica init SubCA IT
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -subject 2>/dev/null | grep -q "TESTICA_SubCA"
}

@test "ica init has ou" {
    # Note: OU is passed as $4 in dispatcher, extra words are lost
    run x509 ica init SubCA IT
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -subject 2>/dev/null | grep -q "IT"
}

@test "ica init has ca true" {
    run x509 ica init SubCA IT
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -text 2>/dev/null | grep -q "CA:TRUE"
}

@test "ica init has pathlen" {
    run x509 ica init SubCA IT
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -text 2>/dev/null | grep -q "pathlen"
}

@test "ica init fullchain contains both certs" {
    run x509 ica init SubCA IT
    assert_success
    # Fullchain should contain ICA cert + root CA cert = 2 certs
    local cert_count
    cert_count=$(grep -c "BEGIN CERTIFICATE" "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca-fullchain.pem")
    assert_equal "2" "${cert_count}"
}

@test "ica init is signed by root ca" {
    run x509 ica init SubCA IT
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" \
        "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" 2>&1 | grep -q "OK"
}

@test "ica init twice fails" {
    run x509 ica init SubCA IT
    assert_success
    run x509 ica init SubCA IT
    assert_failure
    assert_output_contains "already exists"
}

@test "ica init output contains info" {
    run x509 ica init SubCA IT
    assert_success
    # Source has typo: "intermdiate" instead of "intermediate"
    assert_output_contains "certificate authority"
}

@test "ica init removes csr and p12" {
    run x509 ica init SubCA IT
    assert_success
    # ICA init should clean up csr and p12 files
    assert_file_not_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca.csr"
    assert_file_not_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca.p12"
}
