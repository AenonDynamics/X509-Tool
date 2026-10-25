#!/usr/bin/env bats
# Tests for RSA key type and CRT_SCHEME="cn" naming

load helpers

setup() {
    setup_test_workdir
    # Override fixture: RSA keys + cn naming scheme
    sed -i 's/export KEY_TYPE="EC"/export KEY_TYPE="RSA"/' "${TEST_WORKDIR}/cert.conf"
    sed -i 's/CRT_SCHEME="generic"/CRT_SCHEME="cn"/' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- RSA CA ---

@test "rsa ca init creates rsa key" {
    openssl pkey -in "${TEST_WORKDIR}/ca/ca.key" -passin pass:testca1234 -noout -text 2>/dev/null | grep -q "Private-Key.*2048"
}

@test "rsa ca cert uses rsa" {
    openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -text 2>/dev/null | grep -q "rsaEncryption"
}

# --- RSA client with cn naming ---

@test "rsa client add creates cn named files" {
    run x509 client add alice
    assert_success
    # With CRT_SCHEME="cn", files are named after the CN
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.crt"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.key"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.csr"
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.p12"
}

@test "rsa client cert is rsa" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.crt" -noout -text 2>/dev/null | grep -q "rsaEncryption"
}

@test "rsa client key is rsa" {
    run x509 client add alice
    assert_success
    openssl pkey -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.key" -passin pass:testkey1234 -noout -text 2>/dev/null | grep -q "Private-Key.*2048"
}

@test "rsa client is signed by ca" {
    run x509 client add alice
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.crt" 2>&1 | grep -q "OK"
}

# --- RSA server with cn naming ---

@test "rsa server add creates cn named files" {
    run x509 server add web1
    assert_success
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1/TESTSRV_web1.crt"
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1/TESTSRV_web1.p12"
}

@test "rsa server has san" {
    run x509 server add web1 example.com www.example.com
    assert_success
    local san
    san=$(openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1/TESTSRV_web1.crt" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name")
    echo "${san}" | grep -q "DNS:TESTSRV_web1"
    echo "${san}" | grep -q "DNS:example.com"
    echo "${san}" | grep -q "DNS:www.example.com"
}

# --- RSA host with cn naming ---

@test "rsa host add creates cn named files" {
    run x509 host add node1
    assert_success
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/TESTHOST_node1.crt"
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/TESTHOST_node1.p12"
}

# --- RSA codesign with cn naming ---

@test "rsa code add creates cn named files" {
    run x509 code add signer
    assert_success
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_signer/TESTCODE_signer.crt"
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_signer/TESTCODE_signer.p12"
}

# --- RSA smime with cn naming ---

@test "rsa smime add creates cn named files" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/TESTMAIL_alice.crt"
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/TESTMAIL_alice.p12"
}

# --- RSA revoke ---

@test "rsa client revoke works" {
    run x509 client add alice
    assert_success
    run x509 client revoke alice
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/client/TESTCLIENT_alice/TESTCLIENT_alice.crt' 2>&1"
    assert_failure
}

@test "rsa server revoke works" {
    run x509 server add web1
    assert_success
    run x509 server revoke web1
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/server/TESTSRV_web1/TESTSRV_web1.crt' 2>&1"
    assert_failure
}

# --- RSA ICA ---

@test "rsa ica init works" {
    run x509 ica init SubCA IT
    assert_success
    assert_file_exists "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt"
    openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -text 2>/dev/null | grep -q "rsaEncryption"
}
