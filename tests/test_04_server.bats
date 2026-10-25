#!/usr/bin/env bats
# Tests for Server certificate operations: server add, server revoke (with/without SANs)

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- server add (without SANs) ---

@test "server add creates all files" {
    run x509 server add web1.example.com
    assert_success
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt"
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.key"
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.csr"
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.p12"
}

@test "server add uses common name template" {
    run x509 server add web1.example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -subject 2>/dev/null | grep -q "TESTSRV_web1.example.com"
}

@test "server add has serverauth eku" {
    run x509 server add web1.example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -q "TLS Web Server Authentication"
}

@test "server add default san includes cn" {
    run x509 server add web1.example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -q "DNS:TESTSRV_web1.example.com"
}

@test "server add has ca false" {
    run x509 server add web1.example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -q "CA:FALSE"
}

@test "server add is signed by ca" {
    run x509 server add web1.example.com
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" 2>&1 | grep -q "OK"
}

@test "server add has keyencipherment" {
    run x509 server add web1.example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -q "Key Encipherment"
}

# --- server add (with SANs) ---

@test "server add with single san" {
    run x509 server add web1.example.com www.web1.example.com
    assert_success
    local san
    san=$(openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name")
    echo "${san}" | grep -q "DNS:TESTSRV_web1.example.com"
    echo "${san}" | grep -q "DNS:www.web1.example.com"
}

@test "server add with multiple sans" {
    run x509 server add web1.example.com www.web1.example.com api.web1.example.com cdn.web1.example.com
    assert_success
    local san
    san=$(openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name")
    echo "${san}" | grep -q "DNS:TESTSRV_web1.example.com"
    echo "${san}" | grep -q "DNS:www.web1.example.com"
    echo "${san}" | grep -q "DNS:api.web1.example.com"
    echo "${san}" | grep -q "DNS:cdn.web1.example.com"
}

@test "server add with wildcard san" {
    run x509 server add example.com "*.example.com"
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_example.com/server.crt" -noout -text 2>/dev/null | grep -q "DNS:\*.example.com"
}

# --- server revoke ---

@test "server revoke succeeds" {
    run x509 server add web1.example.com
    assert_success
    run x509 server revoke web1.example.com
    assert_success
}

@test "server revoke cert fails verification" {
    run x509 server add web1.example.com
    assert_success
    run x509 server revoke web1.example.com
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt' 2>&1"
    assert_failure
}

@test "server revoke nonexistent fails" {
    run x509 server revoke ghost
    assert_failure
}

@test "server add p12 contains fullchain" {
    run x509 server add web1.example.com
    assert_success
    local cert_count
    cert_count=$(openssl pkcs12 -in "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.p12" \
        -passin pass:testp121234 -nokeys 2>/dev/null | grep -c "BEGIN CERTIFICATE")
    [ "${cert_count}" -ge 2 ]
}
