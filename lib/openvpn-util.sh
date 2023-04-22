#!/usr/bin/env bash

function openvpn_init(){
    # setup ca
    ca_init "$1"

    # add initial server cert
    resolveCertParams "server_cert" "openvpn-server"
    cert_create "server_cert"

    # HMAC auth key setup
    log_info "Generating TLS Auth Key.."
    ${OVPN_BIN} --genkey secret "${CA_DIR}/tls-auth.key"

    # Diffie hellman parameters
    print_heading "Generating DHParams"
    log_warning "Even Modern Systems (XEON/Core i) will take around 10-40min to complete!"
    ${OPENSSL_BIN} dhparam -out "${CA_DIR}/dh${KEY_SIZE}.pem" ${KEY_SIZE}

    # success!
    print_heading "READY!"
}