#!/usr/bin/env bash

# Create a new intermediate ca
# ----------------------------------------------
function ica_init(){

    # resolve common name based on extension
    resolveCertParams "ica_cert" "${1}" "${2}"

    # ica already exists ?
    [ -d "${ICA_DIR}/${KEY_CN}" ] && panic "ICA configuration [${1}] already exists!"

    print_heading "Generating intermdiate certificate authority and structure [${1}]"

    # create config dir
    mkdir -p "${ICA_DIR}/${KEY_CN}"
    ca_create_dir_structure "${ICA_DIR}/${KEY_CN}"

    # create new ca certificate
    cert_create "ica_cert"

    # move ca-crt and key into ca dir
    mv "${CRT_OUTPUT_NAME}.key" "${CRT_STORAGE_DIR}/${KEY_CN}/${CA_DIRNAME}/ca.key"
    mv "${CRT_OUTPUT_NAME}.crt" "${CRT_STORAGE_DIR}/${KEY_CN}/${CA_DIRNAME}/ca.crt"

    # remove csr + p12
    rm "${CRT_OUTPUT_NAME}.p12" "${CRT_OUTPUT_NAME}.csr"

    # copy current cert config
    cp "${WORKING_DIR}/cert.conf" "${CRT_STORAGE_DIR}/${KEY_CN}/cert.conf"

    log_warning "note: cert.conf has been copied but may needs to be modified!"
}