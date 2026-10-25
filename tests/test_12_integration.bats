#!/usr/bin/env bats
# Integration tests: multiple operations, CRL state, cross-cert-type interactions

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# --- Multiple revocations update CRL ---

@test "multiple revocations in crl" {
    run x509 client add alice
    run x509 client add bob
    run x509 client add charlie
    assert_success

    run x509 client revoke alice
    assert_success
    run x509 client revoke bob
    assert_success

    # CRL should contain 2 revoked serials
    local revoked_count
    revoked_count=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${revoked_count}" ] && revoked_count=0
    assert_equal "2" "${revoked_count}"
}

@test "unrevoked cert still verifies" {
    run x509 client add alice
    run x509 client add bob
    assert_success

    run x509 client revoke alice
    assert_success

    # Bob should still verify OK
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_bob/client.crt"
    assert_success
    assert_output_contains "OK"
}

@test "revoked cert fails verification" {
    run x509 client add alice
    run x509 client add bob
    assert_success

    run x509 client revoke alice
    assert_success

    # Alice should fail verification
    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_failure
}

# --- Mixed cert types ---

@test "mixed cert types coexist" {
    run x509 client add alice
    assert_success
    run x509 server add web1
    assert_success
    run x509 host add node1
    assert_success
    run x509 code add signer
    assert_success
    run x509 smime add bob bob@example.com
    assert_success

    # All certs should exist
    assert_file_exists "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_file_exists "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt"
    assert_file_exists "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt"
    assert_file_exists "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt"
    assert_file_exists "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"
}

@test "all cert types verify" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    run x509 code add signer
    run x509 smime add bob bob@example.com
    assert_success

    run x509 verify "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
    assert_success

    run x509 verify "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt"
    assert_success

    run x509 verify "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt"
    assert_success

    run x509 verify "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt"
    assert_success

    run x509 verify "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"
    assert_success
}

# --- Serial numbers are unique across cert types ---

@test "serials unique across types" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    assert_success

    local s1 s2 s3
    s1=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -serial 2>/dev/null)
    s2=$(openssl x509 -in "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" -noout -serial 2>/dev/null)
    s3=$(openssl x509 -in "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" -noout -serial 2>/dev/null)

    [ "${s1}" != "${s2}" ]
    [ "${s2}" != "${s3}" ]
    [ "${s1}" != "${s3}" ]
}

# --- Database tracks all issued certs ---

@test "database tracks issued certs" {
    run x509 client add alice
    run x509 server add web1
    assert_success

    # db.txt should have 2 entries (plus header lines)
    local entry_count
    entry_count=$(grep -c "^V" "${TEST_WORKDIR}/ca/db.txt" || true)
    [ -z "${entry_count}" ] && entry_count=0
    assert_equal "2" "${entry_count}"
}

@test "database marks revoked certs" {
    run x509 client add alice
    run x509 server add web1
    assert_success

    run x509 client revoke alice
    assert_success

    # db.txt should have 1 valid (V) and 1 revoked (R) entry
    local valid_count revoked_count
    valid_count=$(grep -c "^V" "${TEST_WORKDIR}/ca/db.txt" || true)
    revoked_count=$(grep -c "^R" "${TEST_WORKDIR}/ca/db.txt" || true)
    [ -z "${valid_count}" ] && valid_count=0
    [ -z "${revoked_count}" ] && revoked_count=0
    assert_equal "1" "${valid_count}"
    assert_equal "1" "${revoked_count}"
}

# --- p12 files are valid PKCS12 ---

@test "p12 files are valid" {
    run x509 client add alice
    run x509 server add web1
    assert_success

    # Verify p12 can be parsed with the test password
    openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -nokeys 2>/dev/null | grep -q "BEGIN CERTIFICATE"
    openssl pkcs12 -in "${TEST_WORKDIR}/server/TESTSRV_web1/server.p12" \
        -passin pass:testp121234 -nokeys 2>/dev/null | grep -q "BEGIN CERTIFICATE"
}

@test "p12 wrong password fails" {
    run x509 client add alice
    assert_success

    # Wrong password should fail
    run bash -c "openssl pkcs12 -in '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12' -passin pass:wrongpassword -nokeys 2>/dev/null | grep -q 'BEGIN CERTIFICATE'"
    assert_failure
}

# --- ICA chain verification ---

@test "ica fullchain verifies" {
    run x509 ica init SubCA IT
    assert_success

    # The ICA fullchain should verify against the root CA
    openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" \
        -untrusted "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" \
        "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" 2>&1 | grep -q "OK"
}

# --- CRL is regenerated on each revoke ---

@test "crl updated on each revoke" {
    run x509 client add alice
    run x509 client add bob
    run x509 client add charlie
    assert_success

    # Initial CRL has 0 revoked
    local count0
    count0=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${count0}" ] && count0=0

    run x509 client revoke alice
    assert_success
    local count1
    count1=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${count1}" ] && count1=0

    run x509 client revoke bob
    assert_success
    local count2
    count2=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -c "^    Serial Number:" || true)
    [ -z "${count2}" ] && count2=0

    assert_equal "0" "${count0}"
    assert_equal "1" "${count1}"
    assert_equal "2" "${count2}"
}
