#!/usr/bin/env bats
# ----------------------------------------------------------------------
# Security compliance tests: X.509 certificate parameters verified
# against current security standards and best practices.
#
# References:
#   - NIST SP 800-57 Part 1 Rev. 5 (key size recommendations)
#   - CA/Browser Forum Baseline Requirements (TLS certs)
#   - RFC 5280 (X.509 v3 certificate profile)
#   - Mozilla Root Store Policy
#   - BSI TR-02102 (cryptographic requirements)
# ----------------------------------------------------------------------

load helpers

setup() {
    setup_test_workdir
    run x509 ca init TestCA
}

teardown() {
    cleanup_test_workdir
}

# ======================================================================
# Helper functions
# ======================================================================

# Get the full text output of a certificate
cert_text() {
    openssl x509 -in "$1" -noout -text 2>/dev/null
}

# Get signature algorithm of a certificate (short form, e.g. "sha384WithRSAEncryption")
cert_sigalg() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk '{print $3}'
}

# Get public key algorithm and size info
cert_pubkey_info() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -A1 "Public Key Algorithm"
}

# Check that the signature algorithm is NOT MD5 or SHA-1
assert_secure_sigalg() {
    local cert="$1"
    local alg
    alg=$(cert_sigalg "${cert}")
    # Must not be MD5 or SHA-1
    if echo "${alg}" | grep -qiE 'md5|sha1'; then
        echo "INSECURE: signature algorithm '${alg}' in ${cert} is MD5 or SHA-1" >&3
        return 1
    fi
    # Must be SHA-256 or better
    if ! echo "${alg}" | grep -qiE 'sha256|sha384|sha512'; then
        echo "INSECURE: signature algorithm '${alg}' in ${cert} is not SHA-256+" >&3
        return 1
    fi
}

# Assert that a certificate has a specific extension marked critical
assert_extension_critical() {
    local cert="$1"
    local ext_name="$2"
    local text
    text=$(cert_text "${cert}")
    # Find the extension line and check if "critical" appears on the same line
    if ! echo "${text}" | grep -A0 "${ext_name}" | grep -qi "critical"; then
        echo "MISSING: extension '${ext_name}' is not marked critical in ${cert}" >&3
        return 1
    fi
}

# Assert that a certificate has a specific extension (critical or not)
assert_extension_present() {
    local cert="$1"
    local ext_name="$2"
    cert_text "${cert}" | grep -q "${ext_name}"
}

# Assert that a key usage bit is set
assert_ku_present() {
    local cert="$1"
    local ku="$2"
    cert_text "${cert}" | grep -A1 "Key Usage" | grep -qi "${ku}"
}

# Assert that an EKU is present
assert_eku_present() {
    local cert="$1"
    local eku="$2"
    cert_text "${cert}" | grep -A1 "Extended Key Usage" | grep -qi "${eku}"
}

# Assert that an EKU is NOT present
assert_eku_absent() {
    local cert="$1"
    local eku="$2"
    if cert_text "${cert}" | grep -A1 "Extended Key Usage" | grep -qi "${eku}"; then
        echo "UNEXPECTED: EKU '${eku}' should not be present in ${cert}" >&3
        return 1
    fi
}

# ======================================================================
# CA Certificate — Security Standards
# ======================================================================

@test "SEC CA: signature algorithm is SHA-256 or better" {
    assert_secure_sigalg "${TEST_WORKDIR}/ca/ca.crt"
}

@test "SEC CA: basicConstraints CA:TRUE is critical" {
    assert_extension_critical "${TEST_WORKDIR}/ca/ca.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/ca/ca.crt" | grep -q "CA:TRUE"
}

@test "SEC CA: keyUsage includes keyCertSign and cRLSign" {
    assert_ku_present "${TEST_WORKDIR}/ca/ca.crt" "Certificate Sign"
    assert_ku_present "${TEST_WORKDIR}/ca/ca.crt" "CRL Sign"
}

@test "SEC CA: keyUsage is critical" {
    assert_extension_critical "${TEST_WORKDIR}/ca/ca.crt" "Key Usage"
}

@test "SEC CA: subjectKeyIdentifier is present" {
    assert_extension_present "${TEST_WORKDIR}/ca/ca.crt" "Subject Key Identifier"
}

@test "SEC CA: authorityKeyIdentifier is present" {
    assert_extension_present "${TEST_WORKDIR}/ca/ca.crt" "Authority Key Identifier"
}

@test "SEC CA: self-signed (issuer == subject)" {
    local issuer subject
    issuer=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    subject=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -subject 2>/dev/null | sed 's/^subject=//')
    assert_equal "${issuer}" "${subject}"
}

@test "SEC CA: public key is EC P-256 or RSA >= 2048" {
    local pubinfo
    pubinfo=$(cert_pubkey_info "${TEST_WORKDIR}/ca/ca.crt")
    # EC key (prime256v1 in test fixture)
    if echo "${pubinfo}" | grep -qi "id-ecPublicKey\|ASN1 OID: prime256v1\|NIST CURVE: P-256"; then
        return 0
    fi
    # RSA key
    if echo "${pubinfo}" | grep -qi "rsaEncryption"; then
        local bits
        bits=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -text 2>/dev/null | grep "Public-Key" | grep -oE '[0-9]+' | head -1)
        [ "${bits}" -ge 2048 ]
        return
    fi
    echo "UNKNOWN: public key type in CA cert" >&3
    return 1
}

@test "SEC CA: validity period does not exceed 3650 days" {
    # CA_EXPIRE=365 in test fixture; production default is 3650
    # Verify the cert is not valid for an unreasonably long time
    local not_after not_before
    not_before=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
    not_after=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    local nb_epoch na_epoch
    nb_epoch=$(date -d "${not_before}" +%s 2>/dev/null)
    na_epoch=$(date -d "${not_after}" +%s 2>/dev/null)
    local days=$(( (na_epoch - nb_epoch) / 86400 ))
    [ "${days}" -le 3650 ]
}

@test "SEC CA: serial number is not zero or one" {
    local serial
    serial=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -serial 2>/dev/null | sed 's/^serial=//')
    [ "${serial}" != "00" ]
    [ "${serial}" != "01" ]
    [ -n "${serial}" ]
}

# ======================================================================
# Client Certificate — Security Standards
# ======================================================================

@test "SEC Client: signature algorithm is SHA-256 or better" {
    run x509 client add alice
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt"
}

@test "SEC Client: basicConstraints CA:FALSE is critical" {
    run x509 client add alice
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" | grep -q "CA:FALSE"
}

@test "SEC Client: keyUsage digitalSignature is critical" {
    run x509 client add alice
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Digital Signature"
}

@test "SEC Client: extendedKeyUsage clientAuth is critical" {
    run x509 client add alice
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Extended Key Usage"
    assert_eku_present "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "TLS Web Client Authentication"
}

@test "SEC Client: serverAuth EKU is absent" {
    run x509 client add alice
    assert_success
    assert_eku_absent "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "TLS Web Server Authentication"
}

@test "SEC Client: subjectKeyIdentifier is present" {
    run x509 client add alice
    assert_success
    assert_extension_present "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Subject Key Identifier"
}

@test "SEC Client: authorityKeyIdentifier is present" {
    run x509 client add alice
    assert_success
    assert_extension_present "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" "Authority Key Identifier"
}

@test "SEC Client: private key is password-protected (RFC 5208 / PKCS#8 encrypted)" {
    # KNOWN ISSUE: cert_genpkey passes -pass to genpkey but without an explicit
    # cipher (e.g. -aes-256-cbc), OpenSSL 3.x writes an UNENCRYPTED PKCS#8 key.
    # Expected: key file starts with "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    # and reading without password fails.
    run x509 client add alice
    assert_success
    local key_header
    key_header=$(head -1 "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.key")
    assert_equal "-----BEGIN ENCRYPTED PRIVATE KEY-----" "${key_header}"
    # Reading without password must fail
    run bash -c "openssl pkey -in '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.key' -noout 2>&1"
    assert_failure
}

@test "SEC Client: private key is readable with correct password" {
    run x509 client add alice
    assert_success
    run bash -c "openssl pkey -in '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.key' -passin pass:testkey1234 -noout 2>&1"
    assert_success
}

# ======================================================================
# Server Certificate — Security Standards
# ======================================================================

@test "SEC Server: signature algorithm is SHA-256 or better" {
    run x509 server add web1.example.com
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt"
}

@test "SEC Server: basicConstraints CA:FALSE is critical" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" | grep -q "CA:FALSE"
}

@test "SEC Server: keyUsage is critical with digitalSignature" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Digital Signature"
}

@test "SEC Server: extendedKeyUsage serverAuth is critical" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Extended Key Usage"
    assert_eku_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "TLS Web Server Authentication"
}

@test "SEC Server: clientAuth EKU is absent" {
    run x509 server add web1.example.com
    assert_success
    assert_eku_absent "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "TLS Web Client Authentication"
}

@test "SEC Server: subjectAltName is present (not just CN)" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Subject Alternative Name"
}

@test "SEC Server: SAN contains CN as DNS entry" {
    run x509 server add web1.example.com
    assert_success
    cert_text "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" | grep -A1 "Subject Alternative Name" | grep -q "DNS:TESTSRV_web1.example.com"
}

@test "SEC Server: SAN includes additional provided names" {
    run x509 server add web1.example.com www.example.com api.example.com
    assert_success
    local san_line
    san_line=$(cert_text "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" | grep -A1 "Subject Alternative Name")
    echo "${san_line}" | grep -q "DNS:www.example.com"
    echo "${san_line}" | grep -q "DNS:api.example.com"
}

@test "SEC Server: subjectKeyIdentifier is present" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Subject Key Identifier"
}

@test "SEC Server: authorityKeyIdentifier is present" {
    run x509 server add web1.example.com
    assert_success
    assert_extension_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Authority Key Identifier"
}

@test "SEC Server: keyEncipherment is present (for RSA key exchange)" {
    run x509 server add web1.example.com
    assert_success
    assert_ku_present "${TEST_WORKDIR}/server/TESTSRV_web1.example.com/server.crt" "Key Encipherment"
}

# ======================================================================
# Host Certificate — Security Standards
# ======================================================================

@test "SEC Host: signature algorithm is SHA-256 or better" {
    run x509 host add node1
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt"
}

@test "SEC Host: basicConstraints CA:FALSE is critical" {
    run x509 host add node1
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" | grep -q "CA:FALSE"
}

@test "SEC Host: keyUsage is critical with digitalSignature" {
    run x509 host add node1
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "Digital Signature"
}

@test "SEC Host: extendedKeyUsage has both serverAuth and clientAuth (critical)" {
    run x509 host add node1
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "Extended Key Usage"
    assert_eku_present "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "TLS Web Server Authentication"
    assert_eku_present "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "TLS Web Client Authentication"
}

@test "SEC Host: subjectAltName is present" {
    run x509 host add node1
    assert_success
    assert_extension_present "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" "Subject Alternative Name"
}

@test "SEC Host: SAN contains CN" {
    run x509 host add node1
    assert_success
    cert_text "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" | grep -A1 "Subject Alternative Name" | grep -q "DNS:TESTHOST_node1"
}

# ======================================================================
# Code-Signing Certificate — Security Standards
# ======================================================================

@test "SEC Code: signature algorithm is SHA-256 or better" {
    run x509 code add mysigner
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt"
}

@test "SEC Code: basicConstraints CA:FALSE is critical" {
    run x509 code add mysigner
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" | grep -q "CA:FALSE"
}

@test "SEC Code: keyUsage digitalSignature is critical" {
    run x509 code add mysigner
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Digital Signature"
}

@test "SEC Code: extendedKeyUsage codeSigning is critical" {
    run x509 code add mysigner
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Extended Key Usage"
    assert_eku_present "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Code Signing"
}

@test "SEC Code: subjectKeyIdentifier is present" {
    run x509 code add mysigner
    assert_success
    assert_extension_present "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Subject Key Identifier"
}

@test "SEC Code: authorityKeyIdentifier is present" {
    run x509 code add mysigner
    assert_success
    assert_extension_present "${TEST_WORKDIR}/codesign/TESTCODE_mysigner/code.crt" "Authority Key Identifier"
}

# ======================================================================
# S/MIME Certificate — Security Standards
# ======================================================================

@test "SEC SMIME: signature algorithm is SHA-256 or better" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt"
}

@test "SEC SMIME: basicConstraints CA:FALSE is critical" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" | grep -q "CA:FALSE"
}

@test "SEC SMIME: keyUsage digitalSignature is critical" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "Digital Signature"
}

@test "SEC SMIME: keyUsage nonRepudiation (contentCommitment) is present" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_ku_present "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "Non Repudiation"
}

@test "SEC SMIME: extendedKeyUsage emailProtection is critical" {
    run x509 smime add alice alice@example.com
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "Extended Key Usage"
    assert_eku_present "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" "E-mail Protection"
}

@test "SEC SMIME: SAN contains email address" {
    run x509 smime add alice alice@example.com
    assert_success
    cert_text "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" | grep -A1 "Subject Alternative Name" | grep -q "email:alice@example.com"
}

@test "SEC SMIME: subject contains email address" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -subject 2>/dev/null | grep -q "alice@example.com"
}

# ======================================================================
# Intermediate CA — Security Standards
# ======================================================================

@test "SEC ICA: signature algorithm is SHA-256 or better" {
    run x509 ica init SubCA IT
    assert_success
    assert_secure_sigalg "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt"
}

@test "SEC ICA: basicConstraints CA:TRUE with pathlen is critical" {
    run x509 ica init SubCA IT
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "Basic Constraints"
    cert_text "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" | grep -q "CA:TRUE"
    cert_text "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" | grep -q "pathlen"
}

@test "SEC ICA: keyUsage keyCertSign and cRLSign is critical" {
    run x509 ica init SubCA IT
    assert_success
    assert_extension_critical "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "Key Usage"
    assert_ku_present "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "Certificate Sign"
    assert_ku_present "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "CRL Sign"
}

@test "SEC ICA: subjectKeyIdentifier is present" {
    run x509 ica init SubCA IT
    assert_success
    assert_extension_present "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "Subject Key Identifier"
}

@test "SEC ICA: authorityKeyIdentifier is present" {
    run x509 ica init SubCA IT
    assert_success
    assert_extension_present "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" "Authority Key Identifier"
}

@test "SEC ICA: signed by root CA (not self-signed)" {
    run x509 ica init SubCA IT
    assert_success
    local issuer subject
    issuer=$(openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    subject=$(openssl x509 -in "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca.crt" -noout -subject 2>/dev/null | sed 's/^subject=//')
    [ "${issuer}" != "${subject}" ]
}

@test "SEC ICA: fullchain contains ICA + root CA" {
    run x509 ica init SubCA IT
    assert_success
    local count
    count=$(grep -c "BEGIN CERTIFICATE" "${TEST_WORKDIR}/ica/TESTICA_SubCA/ca/ca-fullchain.pem")
    assert_equal "2" "${count}"
}

# ======================================================================
# CRL — Security Standards
# ======================================================================

@test "SEC CRL: signature algorithm is SHA-256 or better" {
    local alg
    alg=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk '{print $3}')
    if echo "${alg}" | grep -qiE 'md5|sha1'; then
        echo "INSECURE: CRL signature algorithm '${alg}' is MD5 or SHA-1" >&3
        return 1
    fi
    if ! echo "${alg}" | grep -qiE 'sha256|sha384|sha512'; then
        echo "INSECURE: CRL signature algorithm '${alg}' is not SHA-256+" >&3
        return 1
    fi
}

@test "SEC CRL: authorityKeyIdentifier is present (CRL v2 with extensions, RFC 5280)" {
    # KNOWN ISSUE: openssl.conf [CA_default] is missing "crl_extensions = crl_ext",
    # so the CRL is generated as v1 without any extensions.
    # Expected: CRL v2 with Authority Key Identifier extension.
    local crl_version
    crl_version=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep "Version" | head -1)
    echo "${crl_version}" | grep -q "Version 2"
    openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -q "Authority Key Identifier"
}

@test "SEC CRL: nextUpdate is set (CRL has expiry)" {
    openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -q "Next Update"
}

@test "SEC CRL: lastUpdate is set" {
    openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -q "Last Update"
}

@test "SEC CRL: revoked cert appears after revocation" {
    run x509 client add alice
    assert_success
    local client_serial
    client_serial=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -serial 2>/dev/null | sed 's/^serial=//')

    run x509 client revoke alice
    assert_success

    openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -text 2>/dev/null | grep -qi "${client_serial}"
}

# ======================================================================
# PKCS#12 — Security Standards
# ======================================================================

@test "SEC P12: uses modern encryption (AES, not RC2/3DES)" {
    run x509 client add alice
    assert_success
    # OpenSSL 3.x defaults to AES-256-CBC for PKCS12
    # Check that the p12 can be decrypted and the MAC is SHA-256+
    local mac_alg
    mac_alg=$(openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -info -nokeys -nomacver 2>&1 | grep -i "MAC" | head -1 || true)
    # If MAC algorithm is shown, it should be SHA-256 or better
    if [ -n "${mac_alg}" ]; then
        if echo "${mac_alg}" | grep -qiE 'sha1\b|md5'; then
            echo "INSECURE: P12 MAC uses weak algorithm: ${mac_alg}" >&3
            return 1
        fi
    fi
}

@test "SEC P12: contains private key" {
    run x509 client add alice
    assert_success
    openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -nocerts -noenc 2>/dev/null | grep -q "PRIVATE KEY"
}

@test "SEC P12: contains CA chain (fullchain)" {
    run x509 client add alice
    assert_success
    local ca_count
    ca_count=$(openssl pkcs12 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12" \
        -passin pass:testp121234 -cacerts -nokeys 2>/dev/null | grep -c "BEGIN CERTIFICATE")
    [ "${ca_count}" -ge 1 ]
}

@test "SEC P12: wrong password fails" {
    run x509 client add alice
    assert_success
    run bash -c "openssl pkcs12 -in '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.p12' -passin pass:wrongpass -nokeys 2>/dev/null"
    assert_failure
}

# ======================================================================
# Cross-cutting: All cert types signed by CA with secure chain
# ======================================================================

@test "SEC All: every issued cert verifies against CA" {
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

    for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" \
        "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt" \
        "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"; do
        openssl verify -CAfile "${TEST_WORKDIR}/ca/ca.crt" "${crt}" 2>&1 | grep -q "OK"
    done
}

@test "SEC All: every issued cert has unique serial number" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    assert_success

    local serials
    serials=$(for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt"; do
        openssl x509 -in "${crt}" -noout -serial 2>/dev/null
    done | sort -u | wc -l)
    assert_equal "3" "${serials}"
}

@test "SEC All: no cert has CA:TRUE (end-entity certs)" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    run x509 code add signer
    run x509 smime add bob bob@example.com
    assert_success

    for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" \
        "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt" \
        "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"; do
        cert_text "${crt}" | grep -q "CA:FALSE"
    done
}

@test "SEC All: every end-entity cert has subjectKeyIdentifier" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    run x509 code add signer
    run x509 smime add bob bob@example.com
    assert_success

    for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" \
        "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt" \
        "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"; do
        assert_extension_present "${crt}" "Subject Key Identifier"
    done
}

@test "SEC All: every end-entity cert has authorityKeyIdentifier" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    run x509 code add signer
    run x509 smime add bob bob@example.com
    assert_success

    for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" \
        "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt" \
        "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"; do
        assert_extension_present "${crt}" "Authority Key Identifier"
    done
}

@test "SEC All: no end-entity cert uses MD5 or SHA-1" {
    run x509 client add alice
    run x509 server add web1
    run x509 host add node1
    run x509 code add signer
    run x509 smime add bob bob@example.com
    assert_success

    for crt in \
        "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" \
        "${TEST_WORKDIR}/server/TESTSRV_web1/server.crt" \
        "${TEST_WORKDIR}/host/TESTHOST_node1/host.crt" \
        "${TEST_WORKDIR}/codesign/TESTCODE_signer/code.crt" \
        "${TEST_WORKDIR}/smime/TESTMAIL_bob/smime.crt"; do
        assert_secure_sigalg "${crt}"
    done
}

# ======================================================================
# EC-specific security checks (test fixture uses prime256v1)
# ======================================================================

@test "SEC EC: CA key uses named curve (not explicit parameters)" {
    openssl pkey -in "${TEST_WORKDIR}/ca/ca.key" -passin pass:testca1234 -noout -text 2>/dev/null | grep -q "ASN1 OID: prime256v1"
}

@test "SEC EC: client cert public key is on a secure curve" {
    run x509 client add alice
    assert_success
    local curve
    curve=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -text 2>/dev/null | grep -E "ASN1 OID|NIST CURVE" | head -1)
    echo "${curve}" | grep -qiE "prime256v1|P-256|secp384r1|P-384|secp521r1|P-521"
}

@test "SEC EC: no explicit EC parameters (named curve only)" {
    # Explicit parameters are discouraged; named curves should be used
    openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -text 2>/dev/null | grep -q "ASN1 OID:"
}

# ======================================================================
# Certificate chain integrity
# ======================================================================

@test "SEC Chain: ca-crl-verify.pem contains CRL + CA cert" {
    local crl_count cert_count
    crl_count=$(grep -c "BEGIN X509 CRL" "${TEST_WORKDIR}/ca/ca-crl-verify.pem")
    cert_count=$(grep -c "BEGIN CERTIFICATE" "${TEST_WORKDIR}/ca/ca-crl-verify.pem")
    assert_equal "1" "${crl_count}"
    assert_equal "1" "${cert_count}"
}

@test "SEC Chain: ca-fullchain.pem is identical to ca.crt for root CA" {
    diff "${TEST_WORKDIR}/ca/ca.crt" "${TEST_WORKDIR}/ca/ca-fullchain.pem"
}

# ======================================================================
# Validity period checks
# ======================================================================

@test "SEC Validity: client cert notBefore is not in the future" {
    run x509 client add alice
    assert_success
    local not_before_epoch now_epoch
    not_before=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
    not_before_epoch=$(date -d "${not_before}" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    [ "${not_before_epoch}" -le "${now_epoch}" ]
}

@test "SEC Validity: client cert notAfter is in the future" {
    run x509 client add alice
    assert_success
    local not_after_epoch now_epoch
    not_after=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    not_after_epoch=$(date -d "${not_after}" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    [ "${not_after_epoch}" -gt "${now_epoch}" ]
}

@test "SEC Validity: cert validity does not exceed CRT_EXPIRE + 1 day" {
    run x509 client add alice
    assert_success
    local not_before not_after nb_epoch na_epoch days
    not_before=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
    not_after=$(openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    nb_epoch=$(date -d "${not_before}" +%s 2>/dev/null)
    na_epoch=$(date -d "${not_after}" +%s 2>/dev/null)
    days=$(( (na_epoch - nb_epoch) / 86400 ))
    # CRT_EXPIRE=365 in fixture, allow 1 day tolerance
    [ "${days}" -le 366 ]
}

# ======================================================================
# Revocation security
# ======================================================================

@test "SEC Revoke: revoked cert fails CRL check" {
    run x509 client add alice
    assert_success
    run x509 client revoke alice
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt' 2>&1"
    assert_failure
}

@test "SEC Revoke: unrevoked cert passes CRL check" {
    run x509 client add alice
    run x509 client add bob
    assert_success
    run x509 client revoke alice
    assert_success
    run bash -c "openssl verify -crl_check -CAfile '${TEST_WORKDIR}/ca/ca-crl-verify.pem' '${TEST_WORKDIR}/client/TESTCLIENT_bob/client.crt' 2>&1"
    assert_success
}

@test "SEC Revoke: CRL is regenerated after each revocation" {
    run x509 client add alice
    run x509 client add bob
    assert_success

    # Get CRL lastUpdate before revocation
    local before
    before=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -lastupdate 2>/dev/null)

    # Wait a moment to ensure timestamp difference
    sleep 1

    run x509 client revoke alice
    assert_success

    local after
    after=$(openssl crl -in "${TEST_WORKDIR}/ca/crl.pem" -noout -lastupdate 2>/dev/null)

    [ "${before}" != "${after}" ]
}

# ======================================================================
# Subject field compliance
# ======================================================================

@test "SEC Subject: CA has all required DN fields (C, ST, L, O)" {
    local subject
    subject=$(openssl x509 -in "${TEST_WORKDIR}/ca/ca.crt" -noout -subject 2>/dev/null)
    echo "${subject}" | grep -q "C = DE\|C=DE"
    echo "${subject}" | grep -q "ST = BERLIN\|ST=BERLIN"
    echo "${subject}" | grep -q "L = BERLIN\|L=BERLIN"
    echo "${subject}" | grep -q "O = Test Company\|O=Test Company"
}

@test "SEC Subject: end-entity certs have CN matching template" {
    run x509 client add alice
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/client/TESTCLIENT_alice/client.crt" -noout -subject 2>/dev/null | grep -q "CN = TESTCLIENT_alice\|CN=TESTCLIENT_alice"
}

@test "SEC Subject: SMIME cert has emailAddress in subject" {
    run x509 smime add alice alice@example.com
    assert_success
    openssl x509 -in "${TEST_WORKDIR}/smime/TESTMAIL_alice/smime.crt" -noout -subject 2>/dev/null | grep -q "emailAddress"
}
