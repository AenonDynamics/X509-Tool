#!/usr/bin/env bats
# ----------------------------------------------------------------------
# Tests for security warnings in environment_check (warn_insecure_parameters)
# Covers: KEY_TYPE, KEY_SIZE, KEY_EC_CURVE, passphrase strength,
#         CRT_EXPIRE, CA_EXPIRE
# ----------------------------------------------------------------------

load helpers

setup() {
    setup_test_workdir
}

teardown() {
    cleanup_test_workdir
}

# ----------------------------------------------------------------------
# Helper: override a single variable in cert.conf and run ca init
# ----------------------------------------------------------------------
run_with_conf() {
    # $1 = variable name, $2 = value, rest = x509 args
    local var="$1" val="$2"
    shift 2
    # Replace the variable in cert.conf
    sed -i "s|^export ${var}=.*|export ${var}=\"${val}\"|" "${TEST_WORKDIR}/cert.conf"
    sed -i "s|^${var}=.*|${var}=\"${val}\"|" "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
}

# Helper: set a non-exported variable (like CA_EXPIRE, CRT_EXPIRE)
set_conf_var() {
    local var="$1" val="$2"
    # Remove existing line and append new one
    sed -i "/^${var}=/d" "${TEST_WORKDIR}/cert.conf"
    echo "${var}=${val}" >> "${TEST_WORKDIR}/cert.conf"
}

# ======================================================================
# KEY_TYPE warnings
# ======================================================================

@test "WARN: KEY_TYPE=DSA produces security warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="DSA"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: KEY_TYPE='DSA' is not recommended"
}

@test "WARN: KEY_TYPE empty produces security warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE=""|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: KEY_TYPE is not set"
}

@test "WARN: KEY_TYPE=EC produces no KEY_TYPE warning" {
    # fixture already uses EC
    run x509 ca init TestCA
    assert_output_not_contains "KEY_TYPE"
}

@test "WARN: KEY_TYPE=RSA produces no KEY_TYPE warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=3072|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "KEY_TYPE"
}

# ======================================================================
# KEY_SIZE warnings (RSA only)
# ======================================================================

@test "WARN: RSA KEY_SIZE=512 produces INSECURE warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=512|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: RSA key size 512 bits is INSECURE"
}

@test "WARN: RSA KEY_SIZE=1024 produces INSECURE warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=1024|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: RSA key size 1024 bits is INSECURE"
}

@test "WARN: RSA KEY_SIZE=2048 produces below-recommended warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=2048|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: RSA key size 2048 bits is below the recommended 3072 bits"
}

@test "WARN: RSA KEY_SIZE=3072 produces no KEY_SIZE warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=3072|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "key size"
}

@test "WARN: RSA KEY_SIZE=4096 produces no KEY_SIZE warning" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=4096|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "key size"
}

@test "WARN: EC KEY_SIZE=512 produces no KEY_SIZE warning (not RSA)" {
    # fixture uses EC — KEY_SIZE is irrelevant for EC
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=512|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "key size"
}

# ======================================================================
# KEY_EC_CURVE warnings (EC only)
# ======================================================================

@test "WARN: EC curve secp160r1 produces whitelist warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp160r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: EC curve 'secp160r1' is not in the recommended whitelist"
}

@test "WARN: EC curve secp192r1 produces whitelist warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp192r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: EC curve 'secp192r1' is not in the recommended whitelist"
}

@test "WARN: EC curve brainpoolP256r1 produces whitelist warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="brainpoolP256r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: EC curve 'brainpoolP256r1' is not in the recommended whitelist"
}

@test "WARN: EC curve empty produces warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE=""|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: KEY_EC_CURVE is not set"
}

@test "WARN: EC curve prime256v1 produces no curve warning" {
    # fixture uses prime256v1
    run x509 ca init TestCA
    assert_output_not_contains "EC curve"
}

@test "WARN: EC curve secp384r1 produces no curve warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp384r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "EC curve"
}

@test "WARN: EC curve secp521r1 produces no curve warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp521r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "EC curve"
}

@test "WARN: EC curve secp256r1 produces no curve warning" {
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp256r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "EC curve"
}

@test "WARN: RSA KEY_EC_CURVE=secp160r1 produces no curve warning (not EC)" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="RSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_SIZE=.*|export KEY_SIZE=3072|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp160r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_not_contains "EC curve"
}

# ======================================================================
# Passphrase strength warnings
# ======================================================================

@test "WARN: 1-character password produces strong warning" {
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CA_PASS_TYPE password is only 1 character(s)"
}

@test "WARN: 7-character password produces strong warning" {
    sed -i 's|^PKEY_PASS_TYPE=.*|PKEY_PASS_TYPE="pass:1234567"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: PKEY_PASS_TYPE password is only 7 character(s)"
}

@test "WARN: 8-character password produces recommended warning" {
    sed -i 's|^P12_PASS_TYPE=.*|P12_PASS_TYPE="pass:12345678"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: P12_PASS_TYPE password is 8 characters — 12+ characters recommended"
}

@test "WARN: 11-character password produces recommended warning" {
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:elevenchars"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CA_PASS_TYPE password is 11 characters — 12+ characters recommended"
}

@test "WARN: 12-character password produces no strength warning" {
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:twelvechars1"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^PKEY_PASS_TYPE=.*|PKEY_PASS_TYPE="pass:twelvechars1"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^P12_PASS_TYPE=.*|P12_PASS_TYPE="pass:twelvechars1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 ca init TestCA
    # The pass: warning contains "the password is visible" — must not match strength warnings
    assert_output_not_contains "password is only"
    assert_output_not_contains "characters — 12+ characters recommended"
}

@test "WARN: env: password produces no strength warning" {
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="env:CAPW"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^PKEY_PASS_TYPE=.*|PKEY_PASS_TYPE="env:PKEYPW"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^P12_PASS_TYPE=.*|P12_PASS_TYPE="env:P12PW"|' "${TEST_WORKDIR}/cert.conf"
    CAPW=testca1234 PKEYPW=testkey1234 P12PW=testp121234 run x509 ca init TestCA
    assert_output_not_contains "password is only"
    assert_output_not_contains "characters — 12+ characters recommended"
}

# ======================================================================
# CRT_EXPIRE warnings
# ======================================================================

@test "WARN: CRT_EXPIRE=3650 produces exceeds-825 warning" {
    set_conf_var "CRT_EXPIRE" "3650"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CRT_EXPIRE=3650 days — end-entity certificates should not exceed 825 days"
}

@test "WARN: CRT_EXPIRE=826 produces exceeds-825 warning" {
    set_conf_var "CRT_EXPIRE" "826"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CRT_EXPIRE=826 days — end-entity certificates should not exceed 825 days"
}

@test "WARN: CRT_EXPIRE=730 produces exceeds-398 warning" {
    set_conf_var "CRT_EXPIRE" "730"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CRT_EXPIRE=730 days exceeds the CA/Browser Forum limit of 398 days"
}

@test "WARN: CRT_EXPIRE=399 produces exceeds-398 warning" {
    set_conf_var "CRT_EXPIRE" "399"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CRT_EXPIRE=399 days exceeds the CA/Browser Forum limit of 398 days"
}

@test "WARN: CRT_EXPIRE=398 produces no expiry warning" {
    set_conf_var "CRT_EXPIRE" "398"
    run x509 ca init TestCA
    assert_output_not_contains "CRT_EXPIRE"
}

@test "WARN: CRT_EXPIRE=365 produces no expiry warning" {
    # fixture uses 365
    run x509 ca init TestCA
    assert_output_not_contains "CRT_EXPIRE"
}

@test "WARN: CRT_EXPIRE=825 produces exceeds-398 warning (not exceeds-825)" {
    set_conf_var "CRT_EXPIRE" "825"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CRT_EXPIRE=825 days exceeds the CA/Browser Forum limit of 398 days"
    assert_output_not_contains "should not exceed 825 days"
}

# ======================================================================
# CA_EXPIRE warnings
# ======================================================================

@test "WARN: CA_EXPIRE=7301 produces exceeds-20-years warning" {
    set_conf_var "CA_EXPIRE" "7301"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CA_EXPIRE=7301 days"
    assert_output_contains "root CA lifetime exceeds 20 years"
}

@test "WARN: CA_EXPIRE=36500 produces exceeds-20-years warning" {
    set_conf_var "CA_EXPIRE" "36500"
    run x509 ca init TestCA
    assert_output_contains "SECURITY: CA_EXPIRE=36500 days"
    assert_output_contains "100 years"
}

@test "WARN: CA_EXPIRE=7300 produces no CA_EXPIRE warning" {
    set_conf_var "CA_EXPIRE" "7300"
    run x509 ca init TestCA
    assert_output_not_contains "CA_EXPIRE"
}

@test "WARN: CA_EXPIRE=3650 produces no CA_EXPIRE warning" {
    # fixture uses 365
    run x509 ca init TestCA
    assert_output_not_contains "CA_EXPIRE"
}

# ======================================================================
# Combined: multiple warnings at once
# ======================================================================

@test "WARN: multiple insecure params produce multiple warnings" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="DSA"|' "${TEST_WORKDIR}/cert.conf"
    sed -i 's|^CA_PASS_TYPE=.*|CA_PASS_TYPE="pass:1"|' "${TEST_WORKDIR}/cert.conf"
    set_conf_var "CRT_EXPIRE" "3650"
    set_conf_var "CA_EXPIRE" "36500"
    run x509 ca init TestCA
    assert_output_contains "KEY_TYPE='DSA' is not recommended"
    assert_output_contains "CA_PASS_TYPE password is only 1 character(s)"
    assert_output_contains "CRT_EXPIRE=3650 days"
    assert_output_contains "CA_EXPIRE=36500 days"
}

# ======================================================================
# Warnings appear for non-ca commands too (client add, server add, etc.)
# ======================================================================

@test "WARN: warnings appear on client add" {
    run x509 ca init TestCA
    assert_success
    sed -i 's|^export KEY_EC_CURVE=.*|export KEY_EC_CURVE="secp160r1"|' "${TEST_WORKDIR}/cert.conf"
    run x509 client add alice
    assert_output_contains "SECURITY: EC curve 'secp160r1' is not in the recommended whitelist"
}

@test "WARN: warnings appear on util genpkey" {
    sed -i 's|^export KEY_TYPE=.*|export KEY_TYPE="DSA"|' "${TEST_WORKDIR}/cert.conf"
    run x509 util genpkey "${TEST_WORKDIR}/test.key"
    assert_output_contains "SECURITY: KEY_TYPE='DSA' is not recommended"
}

# ======================================================================
# Secure configuration: no parameter warnings (only pass: warnings from fixture)
# ======================================================================

@test "WARN: secure fixture produces no parameter warnings" {
    run x509 ca init TestCA
    # fixture uses: EC, prime256v1, CRT_EXPIRE=365, CA_EXPIRE=365
    # Only pass: warnings and short-password warnings should appear (fixture passwords are 10-11 chars)
    assert_output_not_contains "KEY_TYPE"
    assert_output_not_contains "key size"
    assert_output_not_contains "EC curve"
    assert_output_not_contains "CRT_EXPIRE"
    assert_output_not_contains "CA_EXPIRE"
    assert_output_not_contains "password is only"  # fixture passwords are >= 8 chars
}
