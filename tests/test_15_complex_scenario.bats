#!/usr/bin/env bats
# Complex scenario integration test:
# 1 root CA + 3 intermediate CAs, each ICA in its own temp working dir
# with a complete independent CA tree. 20 certificates per ICA.
# Tests: create, renew (replace), revoke for each ICA.

load helpers

# ----------------------------------------------------------------------
# Helper: run x509-tool in an arbitrary directory (not TEST_WORKDIR)
# ----------------------------------------------------------------------
x509_in_dir() {
    local dir="$1"
    shift
    (
        cd "${dir}" || exit 99
        CONF_DIR="${TOOL_DIR}" \
        LIB_DIR="${TOOL_DIR}/lib" \
        OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}" \
        OVPN_BIN="${OVPN_BIN:-/usr/sbin/openvpn}" \
        bash "${TOOL_DIR}/x509-tool" "$@"
    )
}

# Helper: run x509-tool with "y" piped to stdin (for renew/replace prompt)
x509_in_dir_yes() {
    local dir="$1"
    shift
    (
        cd "${dir}" || exit 99
        echo "y" | CONF_DIR="${TOOL_DIR}" \
        LIB_DIR="${TOOL_DIR}/lib" \
        OPENSSL_BIN="${OPENSSL_BIN:-/usr/bin/openssl}" \
        OVPN_BIN="${OVPN_BIN:-/usr/sbin/openvpn}" \
        bash "${TOOL_DIR}/x509-tool" "$@"
    )
}

# ----------------------------------------------------------------------
# Helper: create 20 client certificates (cert01..cert20) in a cert dir
# ----------------------------------------------------------------------
create_20_certs() {
    local cert_dir="$1"
    local i
    for i in $(seq -w 1 20); do
        run x509_in_dir "${cert_dir}" client add "cert${i}"
        assert_success
    done
}

# Helper: read serial number from a cert file
get_serial() {
    openssl x509 -in "$1" -noout -serial 2>/dev/null | cut -d= -f2
}

# Helper: count valid (V) entries in db.txt
count_valid() {
    local count
    count=$(grep -c "^V" "$1" 2>/dev/null) || count=0
    echo "${count}"
}

# Helper: count revoked (R) entries in db.txt
count_revoked() {
    local count
    count=$(grep -c "^R" "$1" 2>/dev/null) || count=0
    echo "${count}"
}

# Helper: count revoked serials in a CRL
count_crl_entries() {
    local count
    count=$(openssl crl -in "$1" -noout -text 2>/dev/null | grep -c "^    Serial Number:") || count=0
    echo "${count}"
}

# Helper: verify a cert against an ICA's full chain + CRL.
# x509-tool's built-in verify uses ca-crl-verify.pem which in an ICA sub-tree
# contains only CRL + ICA cert (no root CA), so we call openssl verify directly.
verify_in_ica() {
    local ica_workdir="$1"
    local ica_cert_dir="$2"
    local cert_file="$3"
    openssl verify -crl_check \
        -CAfile "${ica_workdir}/ca/ca.crt" \
        -untrusted "${ica_cert_dir}/ca/ca.crt" \
        -CRLfile "${ica_cert_dir}/ca/crl.pem" \
        "${cert_file}" 2>&1
}

# ======================================================================
# setup / teardown
# ======================================================================

setup() {
    setup_test_workdir

    # 1 root CA in the main test workdir
    run x509 ca init TestCA
    assert_success

    # 3 ICA working directories — each gets its own complete CA tree
    ICA1_WORKDIR="$(mktemp -d /tmp/x509-ica1-XXXXXX)"
    ICA2_WORKDIR="$(mktemp -d /tmp/x509-ica2-XXXXXX)"
    ICA3_WORKDIR="$(mktemp -d /tmp/x509-ica3-XXXXXX)"

    # copy cert.conf fixture into each ICA workdir
    cp "${TEST_FIXTURES_DIR}/cert.conf" "${ICA1_WORKDIR}/cert.conf"
    cp "${TEST_FIXTURES_DIR}/cert.conf" "${ICA2_WORKDIR}/cert.conf"
    cp "${TEST_FIXTURES_DIR}/cert.conf" "${ICA3_WORKDIR}/cert.conf"

    # ICA1: own root CA + intermediate CA
    run x509_in_dir "${ICA1_WORKDIR}" ca init SubCA1
    assert_success
    run x509_in_dir "${ICA1_WORKDIR}" ica init ICA1 DE
    assert_success

    # ICA2: own root CA + intermediate CA
    run x509_in_dir "${ICA2_WORKDIR}" ca init SubCA2
    assert_success
    run x509_in_dir "${ICA2_WORKDIR}" ica init ICA2 DE
    assert_success

    # ICA3: own root CA + intermediate CA
    run x509_in_dir "${ICA3_WORKDIR}" ca init SubCA3
    assert_success
    run x509_in_dir "${ICA3_WORKDIR}" ica init ICA3 DE
    assert_success

    # Directory inside each ICA workdir where certs are issued (signed by the ICA)
    ICA1_CERT_DIR="${ICA1_WORKDIR}/ica/TESTICA_ICA1"
    ICA2_CERT_DIR="${ICA2_WORKDIR}/ica/TESTICA_ICA2"
    ICA3_CERT_DIR="${ICA3_WORKDIR}/ica/TESTICA_ICA3"

    # openssl.conf references RANDFILE=$CA_DIR/.rnd — the ICA ca dir needs one
    # (normally created as a side-effect of `ca init` in the root, but the ICA
    #  sub-tree is built by ica_init which doesn't seed it)
    openssl rand -out "${ICA1_CERT_DIR}/ca/.rnd" 1024
    openssl rand -out "${ICA2_CERT_DIR}/ca/.rnd" 1024
    openssl rand -out "${ICA3_CERT_DIR}/ca/.rnd" 1024

    # ica_init creates the ICA key via cert_create which uses PKEY_PASS_TYPE,
    # but openssl ca loads the CA key with CA_PASS_TYPE. Align CA_PASS_TYPE in
    # the ICA's cert.conf so that openssl ca can decrypt the ICA private key.
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:testkey1234"|' "${ICA1_CERT_DIR}/cert.conf"
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:testkey1234"|' "${ICA2_CERT_DIR}/cert.conf"
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:testkey1234"|' "${ICA3_CERT_DIR}/cert.conf"

    # ica_init does not create a CRL (crl_create is only called by ca_init and
    # cert_revoke). Seed an empty CRL so that verify works before any revoke.
    # openssl.conf references several $ENV::KEY_* variables that are normally
    # set by the tool at runtime — provide them explicitly.
    local ica_cert_dir
    for ica_cert_dir in "${ICA1_CERT_DIR}" "${ICA2_CERT_DIR}" "${ICA3_CERT_DIR}"; do
        (
            source "${ica_cert_dir}/cert.conf"
            export KEY_CN="dummy"
            export KEY_SAN="DNS:dummy"
            CA_DIR="${ica_cert_dir}/ca" openssl ca -batch \
                -config "${TOOL_DIR}/openssl.conf" \
                -passin pass:testkey1234 \
                -gencrl \
                -out "${ica_cert_dir}/ca/crl.pem" 2>/dev/null || true
        )
    done
}

teardown() {
    cleanup_test_workdir
    rm -rf "${ICA1_WORKDIR}" "${ICA2_WORKDIR}" "${ICA3_WORKDIR}"
}

# ======================================================================
# ICA1 — create 20 certificates
# ======================================================================

@test "complex ICA1: create 20 certificates" {
    create_20_certs "${ICA1_CERT_DIR}"

    # all 20 cert files exist
    local i
    for i in $(seq -w 1 20); do
        assert_file_exists "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
        assert_file_exists "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.key"
        assert_file_exists "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.p12"
    done

    # db has 20 valid entries, 0 revoked
    assert_equal "20" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "0"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"

    # CRL is empty
    assert_equal "0" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"
}

@test "complex ICA1: certificates signed by ICA1" {
    create_20_certs "${ICA1_CERT_DIR}"

    # issuer of cert01 must be the ICA1
    openssl x509 -in "${ICA1_CERT_DIR}/client/TESTCLIENT_cert01/client.crt" \
        -noout -issuer 2>/dev/null | grep -q "TESTICA_ICA1"

    # verify chain: root CA -> ICA -> client cert
    run bash -c "openssl verify -CAfile '${ICA1_WORKDIR}/ca/ca.crt' \
        -untrusted '${ICA1_CERT_DIR}/ca/ca.crt' \
        '${ICA1_CERT_DIR}/client/TESTCLIENT_cert01/client.crt' 2>&1"
    assert_success
}

@test "complex ICA1: all 20 certs have unique serials" {
    create_20_certs "${ICA1_CERT_DIR}"

    local serials
    serials=$(for i in $(seq -w 1 20); do
        get_serial "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
    done | sort -u | wc -l)
    assert_equal "20" "${serials}"
}

# ======================================================================
# ICA1 — renew (replace) certificates
# ======================================================================

@test "complex ICA1: renew 5 certificates changes serials" {
    create_20_certs "${ICA1_CERT_DIR}"

    # save serials of cert01..cert05 before renew
    local old_serials=()
    local i
    for i in 01 02 03 04 05; do
        old_serials+=("$(get_serial "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")")
    done

    # renew: re-add with "y" confirmation
    for i in 01 02 03 04 05; do
        run x509_in_dir_yes "${ICA1_CERT_DIR}" client add "cert${i}"
        assert_success
    done

    # serials must have changed
    local idx new_serial
    for idx in 0 1 2 3 4; do
        i=$(printf "%02d" "$((idx + 1))")
        new_serial=$(get_serial "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")
        [ "${old_serials[$idx]}" != "${new_serial}" ]
    done
}

@test "complex ICA1: renew revokes old certs (CRL grows)" {
    create_20_certs "${ICA1_CERT_DIR}"

    # CRL starts empty
    assert_equal "0" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # renew cert01..cert05
    local i
    for i in 01 02 03 04 05; do
        run x509_in_dir_yes "${ICA1_CERT_DIR}" client add "cert${i}"
        assert_success
    done

    # CRL now has 5 entries (old certs were revoked)
    assert_equal "5" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # db: 15 valid (cert06..cert20) + 5 renewed = 20 valid, 5 revoked
    assert_equal "20" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA1: renewed cert verifies, old serial is in CRL" {
    create_20_certs "${ICA1_CERT_DIR}"

    # save old cert
    local old_crt="${ICA1_CERT_DIR}/client/TESTCLIENT_cert01/client.crt"
    cp "${old_crt}" /tmp/old_cert01.pem

    # renew
    run x509_in_dir_yes "${ICA1_CERT_DIR}" client add cert01
    assert_success

    # new cert verifies OK
    run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${old_crt}"
    assert_success

    # old cert (saved copy) should fail verification (revoked)
    run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" /tmp/old_cert01.pem
    assert_failure
    rm -f /tmp/old_cert01.pem
}

# ======================================================================
# ICA1 — revoke certificates
# ======================================================================

@test "complex ICA1: revoke 3 certificates" {
    create_20_certs "${ICA1_CERT_DIR}"

    local i
    for i in 06 07 08; do
        run x509_in_dir "${ICA1_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    # CRL has 3 entries
    assert_equal "3" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # db: 17 valid, 3 revoked
    assert_equal "17" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "3"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA1: revoked cert fails verification" {
    create_20_certs "${ICA1_CERT_DIR}"

    run x509_in_dir "${ICA1_CERT_DIR}" client revoke cert01
    assert_success

    run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert01/client.crt"
    assert_failure
}

@test "complex ICA1: unrevoked cert still verifies after sibling revoked" {
    create_20_certs "${ICA1_CERT_DIR}"

    run x509_in_dir "${ICA1_CERT_DIR}" client revoke cert01
    assert_success

    # cert02 should still verify
    run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert02/client.crt"
    assert_success
    assert_output_contains "OK"
}

@test "complex ICA1: revoke all 20 certificates" {
    create_20_certs "${ICA1_CERT_DIR}"

    local i
    for i in $(seq -w 1 20); do
        run x509_in_dir "${ICA1_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    # CRL has 20 entries
    assert_equal "20" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # db: 0 valid, 20 revoked
    assert_equal "0"  "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "20" "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"

    # no cert verifies anymore
    run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert10/client.crt"
    assert_failure
}

# ======================================================================
# ICA2 — create, renew, revoke
# ======================================================================

@test "complex ICA2: create 20 certificates" {
    create_20_certs "${ICA2_CERT_DIR}"

    local i
    for i in $(seq -w 1 20); do
        assert_file_exists "${ICA2_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
    done

    assert_equal "20" "$(count_valid "${ICA2_CERT_DIR}/ca/db.txt")"
    assert_equal "0"  "$(count_revoked "${ICA2_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA2: certificates signed by ICA2" {
    create_20_certs "${ICA2_CERT_DIR}"

    openssl x509 -in "${ICA2_CERT_DIR}/client/TESTCLIENT_cert01/client.crt" \
        -noout -issuer 2>/dev/null | grep -q "TESTICA_ICA2"

    run bash -c "openssl verify -CAfile '${ICA2_WORKDIR}/ca/ca.crt' \
        -untrusted '${ICA2_CERT_DIR}/ca/ca.crt' \
        '${ICA2_CERT_DIR}/client/TESTCLIENT_cert01/client.crt' 2>&1"
    assert_success
}

@test "complex ICA2: renew 5 certificates" {
    create_20_certs "${ICA2_CERT_DIR}"

    local old_serials=()
    local i
    for i in 01 02 03 04 05; do
        old_serials+=("$(get_serial "${ICA2_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")")
    done

    for i in 01 02 03 04 05; do
        run x509_in_dir_yes "${ICA2_CERT_DIR}" client add "cert${i}"
        assert_success
    done

    local idx new_serial
    for idx in 0 1 2 3 4; do
        i=$(printf "%02d" "$((idx + 1))")
        new_serial=$(get_serial "${ICA2_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")
        [ "${old_serials[$idx]}" != "${new_serial}" ]
    done

    assert_equal "5" "$(count_crl_entries "${ICA2_CERT_DIR}/ca/crl.pem")"
    assert_equal "20" "$(count_valid "${ICA2_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA2_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA2: revoke 3 certificates" {
    create_20_certs "${ICA2_CERT_DIR}"

    local i
    for i in 06 07 08; do
        run x509_in_dir "${ICA2_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    assert_equal "3"  "$(count_crl_entries "${ICA2_CERT_DIR}/ca/crl.pem")"
    assert_equal "17" "$(count_valid "${ICA2_CERT_DIR}/ca/db.txt")"
    assert_equal "3"  "$(count_revoked "${ICA2_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA2: revoked cert fails verification" {
    create_20_certs "${ICA2_CERT_DIR}"

    run x509_in_dir "${ICA2_CERT_DIR}" client revoke cert01
    assert_success

    run verify_in_ica "${ICA2_WORKDIR}" "${ICA2_CERT_DIR}" "${ICA2_CERT_DIR}/client/TESTCLIENT_cert01/client.crt"
    assert_failure
}

@test "complex ICA2: unrevoked cert still verifies" {
    create_20_certs "${ICA2_CERT_DIR}"

    run x509_in_dir "${ICA2_CERT_DIR}" client revoke cert01
    assert_success

    run verify_in_ica "${ICA2_WORKDIR}" "${ICA2_CERT_DIR}" "${ICA2_CERT_DIR}/client/TESTCLIENT_cert02/client.crt"
    assert_success
}

# ======================================================================
# ICA3 — create, renew, revoke
# ======================================================================

@test "complex ICA3: create 20 certificates" {
    create_20_certs "${ICA3_CERT_DIR}"

    local i
    for i in $(seq -w 1 20); do
        assert_file_exists "${ICA3_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
    done

    assert_equal "20" "$(count_valid "${ICA3_CERT_DIR}/ca/db.txt")"
    assert_equal "0"  "$(count_revoked "${ICA3_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA3: certificates signed by ICA3" {
    create_20_certs "${ICA3_CERT_DIR}"

    openssl x509 -in "${ICA3_CERT_DIR}/client/TESTCLIENT_cert01/client.crt" \
        -noout -issuer 2>/dev/null | grep -q "TESTICA_ICA3"

    run bash -c "openssl verify -CAfile '${ICA3_WORKDIR}/ca/ca.crt' \
        -untrusted '${ICA3_CERT_DIR}/ca/ca.crt' \
        '${ICA3_CERT_DIR}/client/TESTCLIENT_cert01/client.crt' 2>&1"
    assert_success
}

@test "complex ICA3: renew 5 certificates" {
    create_20_certs "${ICA3_CERT_DIR}"

    local old_serials=()
    local i
    for i in 01 02 03 04 05; do
        old_serials+=("$(get_serial "${ICA3_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")")
    done

    for i in 01 02 03 04 05; do
        run x509_in_dir_yes "${ICA3_CERT_DIR}" client add "cert${i}"
        assert_success
    done

    local idx new_serial
    for idx in 0 1 2 3 4; do
        i=$(printf "%02d" "$((idx + 1))")
        new_serial=$(get_serial "${ICA3_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt")
        [ "${old_serials[$idx]}" != "${new_serial}" ]
    done

    assert_equal "5" "$(count_crl_entries "${ICA3_CERT_DIR}/ca/crl.pem")"
    assert_equal "20" "$(count_valid "${ICA3_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA3_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA3: revoke 3 certificates" {
    create_20_certs "${ICA3_CERT_DIR}"

    local i
    for i in 06 07 08; do
        run x509_in_dir "${ICA3_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    assert_equal "3"  "$(count_crl_entries "${ICA3_CERT_DIR}/ca/crl.pem")"
    assert_equal "17" "$(count_valid "${ICA3_CERT_DIR}/ca/db.txt")"
    assert_equal "3"  "$(count_revoked "${ICA3_CERT_DIR}/ca/db.txt")"
}

@test "complex ICA3: revoked cert fails verification" {
    create_20_certs "${ICA3_CERT_DIR}"

    run x509_in_dir "${ICA3_CERT_DIR}" client revoke cert01
    assert_success

    run verify_in_ica "${ICA3_WORKDIR}" "${ICA3_CERT_DIR}" "${ICA3_CERT_DIR}/client/TESTCLIENT_cert01/client.crt"
    assert_failure
}

@test "complex ICA3: unrevoked cert still verifies" {
    create_20_certs "${ICA3_CERT_DIR}"

    run x509_in_dir "${ICA3_CERT_DIR}" client revoke cert01
    assert_success

    run verify_in_ica "${ICA3_WORKDIR}" "${ICA3_CERT_DIR}" "${ICA3_CERT_DIR}/client/TESTCLIENT_cert02/client.crt"
    assert_success
}

# ======================================================================
# Cross-ICA isolation tests
# ======================================================================

@test "complex: ICAs are fully isolated (separate db, CRL, keys)" {
    create_20_certs "${ICA1_CERT_DIR}"
    create_20_certs "${ICA2_CERT_DIR}"

    # each ICA has its own 20 valid entries
    assert_equal "20" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "20" "$(count_valid "${ICA2_CERT_DIR}/ca/db.txt")"

    # revoke in ICA1 does not affect ICA2
    run x509_in_dir "${ICA1_CERT_DIR}" client revoke cert01
    assert_success

    assert_equal "1" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"
    assert_equal "0" "$(count_crl_entries "${ICA2_CERT_DIR}/ca/crl.pem")"

    # ICA2 cert02 still verifies
    run verify_in_ica "${ICA2_WORKDIR}" "${ICA2_CERT_DIR}" "${ICA2_CERT_DIR}/client/TESTCLIENT_cert02/client.crt"
    assert_success
}

@test "complex: ICA1 cert does not verify against ICA2 CA" {
    create_20_certs "${ICA1_CERT_DIR}"
    create_20_certs "${ICA2_CERT_DIR}"

    # ICA1 cert01 signed by ICA1 — should NOT verify against ICA2's CA chain
    run bash -c "openssl verify -CAfile '${ICA2_WORKDIR}/ca/ca.crt' \
        -untrusted '${ICA2_CERT_DIR}/ca/ca.crt' \
        '${ICA1_CERT_DIR}/client/TESTCLIENT_cert01/client.crt' 2>&1"
    assert_failure
}

@test "complex: ICA keys are different across ICAs" {
    # ICA1 and ICA2 must have different CA keys
    # (ICA keys are encrypted with PKEY_PASS_TYPE by ica_init/cert_create)
    local key1 key2
    key1=$(openssl pkey -in "${ICA1_CERT_DIR}/ca/ca.key" -passin pass:testkey1234 -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
    key2=$(openssl pkey -in "${ICA2_CERT_DIR}/ca/ca.key" -passin pass:testkey1234 -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
    [ "${key1}" != "${key2}" ]
}

@test "complex: root CA in main workdir is independent from ICA workdirs" {
    # main root CA exists
    assert_file_exists "${TEST_WORKDIR}/ca/ca.crt"

    # ICA root CAs are different from main root CA
    local main_key ica1_key
    main_key=$(openssl pkey -in "${TEST_WORKDIR}/ca/ca.key" -passin pass:testca1234 -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
    ica1_key=$(openssl pkey -in "${ICA1_WORKDIR}/ca/ca.key" -passin pass:testca1234 -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)
    [ "${main_key}" != "${ica1_key}" ]
}

# ======================================================================
# Combined lifecycle: create -> renew -> revoke in one ICA
# ======================================================================

@test "complex ICA1: full lifecycle create+renew+revoke" {
    # Step 1: create 20
    create_20_certs "${ICA1_CERT_DIR}"
    assert_equal "20" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "0"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"

    # Step 2: renew cert01..cert05 (old ones get revoked)
    local i
    for i in 01 02 03 04 05; do
        run x509_in_dir_yes "${ICA1_CERT_DIR}" client add "cert${i}"
        assert_success
    done
    assert_equal "20" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # Step 3: revoke cert06..cert10
    for i in 06 07 08 09 10; do
        run x509_in_dir "${ICA1_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done
    assert_equal "15" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "10" "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "10" "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # Step 4: renewed certs still verify
    for i in 01 02 03 04 05; do
        run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
        assert_success
    done

    # Step 5: revoked certs fail verification
    for i in 06 07 08 09 10; do
        run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
        assert_failure
    done

    # Step 6: untouched certs (11..20) still verify
    for i in 11 12 13 14 15 16 17 18 19 20; do
        run verify_in_ica "${ICA1_WORKDIR}" "${ICA1_CERT_DIR}" "${ICA1_CERT_DIR}/client/TESTCLIENT_cert${i}/client.crt"
        assert_success
    done
}

# ======================================================================
# Aggregate: total certificates across all 3 ICAs
# ======================================================================

@test "complex: total 60 certificates across all 3 ICAs" {
    create_20_certs "${ICA1_CERT_DIR}"
    create_20_certs "${ICA2_CERT_DIR}"
    create_20_certs "${ICA3_CERT_DIR}"

    local total
    total=$(find "${ICA1_CERT_DIR}/client" "${ICA2_CERT_DIR}/client" "${ICA3_CERT_DIR}/client" \
        -name "client.crt" -type f 2>/dev/null | wc -l)
    assert_equal "60" "${total}"
}

@test "complex: total valid entries across all 3 ICA databases" {
    create_20_certs "${ICA1_CERT_DIR}"
    create_20_certs "${ICA2_CERT_DIR}"
    create_20_certs "${ICA3_CERT_DIR}"

    local total_valid
    total_valid=$(cat "${ICA1_CERT_DIR}/ca/db.txt" \
                       "${ICA2_CERT_DIR}/ca/db.txt" \
                       "${ICA3_CERT_DIR}/ca/db.txt" \
        | grep -c "^V" || echo "0")
    assert_equal "60" "${total_valid}"
}

@test "complex: mixed operations across all 3 ICAs" {
    # ICA1: create 20, renew 3, revoke 2
    create_20_certs "${ICA1_CERT_DIR}"
    local i
    for i in 01 02 03; do
        run x509_in_dir_yes "${ICA1_CERT_DIR}" client add "cert${i}"
        assert_success
    done
    for i in 04 05; do
        run x509_in_dir "${ICA1_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    # ICA2: create 20, revoke 5
    create_20_certs "${ICA2_CERT_DIR}"
    for i in 01 02 03 04 05; do
        run x509_in_dir "${ICA2_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    # ICA3: create 20, renew 10, revoke 3
    create_20_certs "${ICA3_CERT_DIR}"
    for i in $(seq -w 1 10); do
        run x509_in_dir_yes "${ICA3_CERT_DIR}" client add "cert${i}"
        assert_success
    done
    for i in 11 12 13; do
        run x509_in_dir "${ICA3_CERT_DIR}" client revoke "cert${i}"
        assert_success
    done

    # ICA1: 18 valid, 5 revoked (3 renew-revoked + 2 explicit revoke)
    assert_equal "18" "$(count_valid "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA1_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_crl_entries "${ICA1_CERT_DIR}/ca/crl.pem")"

    # ICA2: 15 valid, 5 revoked
    assert_equal "15" "$(count_valid "${ICA2_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_revoked "${ICA2_CERT_DIR}/ca/db.txt")"
    assert_equal "5"  "$(count_crl_entries "${ICA2_CERT_DIR}/ca/crl.pem")"

    # ICA3: 17 valid, 13 revoked (10 renew-revoked + 3 explicit revoke)
    assert_equal "17" "$(count_valid "${ICA3_CERT_DIR}/ca/db.txt")"
    assert_equal "13" "$(count_revoked "${ICA3_CERT_DIR}/ca/db.txt")"
    assert_equal "13" "$(count_crl_entries "${ICA3_CERT_DIR}/ca/crl.pem")"
}
