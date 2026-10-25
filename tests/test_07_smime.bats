#!/usr/bin/env bats
# Tests for S/MIME certificate operations: smime add, smime revoke

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- smime add ---

@test "smime add creates all files" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt"
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.key"
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.csr"
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.p12"
}

@test "smime add uses common name template" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -subject 2>/dev/null | grep -q "TESTMAIL_alice"
}

@test "smime add has email in subject" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -subject 2>/dev/null | grep -q "alice@example.com"
}

@test "smime add has emailprotection eku" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -text 2>/dev/null | grep -qi "E-mail Protection"
}

@test "smime add has clientauth eku" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -text 2>/dev/null | grep -q "TLS Web Client Authentication"
}

@test "smime add has email san" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -text 2>/dev/null | grep -q "email:alice@example.com"
}

@test "smime add has ca false" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -text 2>/dev/null | grep -q "CA:FALSE"
}

@test "smime add has nonrepudiation ku" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -text 2>/dev/null | grep -qi "Non Repudiation"
}

@test "smime add is signed by ca" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" 2>&1 | grep -q "OK"
}

@test "smime add cert not empty" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_file_not_empty "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt"
    assert_file_not_empty "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.p12"
}

# --- smime revoke ---

@test "smime revoke succeeds" {
    run x509 smime add alice alice@example.com
    assert_success
    run x509 smime revoke alice
    assert_success
}

@test "smime revoke cert fails verification" {
    run x509 smime add alice alice@example.com
    assert_success
    run x509 smime revoke alice
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt' 2>&1"
    assert_failure
}

@test "smime revoke nonexistent fails" {
    run x509 smime revoke ghost
    assert_failure
}

@test "smime revoke output contains revoking" {
    run x509 smime add alice alice@example.com
    assert_success
    run x509 smime revoke alice
    assert_success
    assert_output_contains "revoking cert"
}
