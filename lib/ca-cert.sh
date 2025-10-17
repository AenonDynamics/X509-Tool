#!/usr/bin/env bash

# Create CA + directory structure
# ----------------------------------------------
function ca_init(){
    # directory already exists ?
    if [ -d "${CA_DIR}" ] || [ -d "${SERVER_DIR}" ]; then
        panic "configuration ${1} already exists!"
    fi

    print_heading "Initializing CA [${1}]"

    ca_create_dir_structure "${WORKING_DIR}"

    # Set Common Name
    export KEY_CN="$(printf "${CA_COMMON_NAME}" "${1}")"

    # create new private key
    cert_genpkey "${CA_DIR}/ca.key" "${CA_PASS_TYPE}"

    # Create CA
    print_heading "creating CA.."
    ${OPENSSL_BIN} req \
        -config "${CONF_DIR}/openssl.conf" \
        -days ${CA_EXPIRE} \
        -new \
        -x509 \
        -key "${CA_DIR}/ca.key" \
        -out "${CA_DIR}/ca.crt"

    # copy ca to chain file
    cp "${CA_DIR}/ca.crt" "${CA_DIR}/ca-fullchain.pem"

    # show CA cert
    cert_show "${CA_DIR}/ca.crt"

    # Create CRL
    crl_create
}

# ca dir structure + required serial + db files
# ----------------------------------------------
function ca_create_dir_structure(){

    # create config dir
    log_info "creating CA directory structure.."
    mkdir "${1}/${CA_DIRNAME}"
    mkdir "${1}/${ICA_DIRNAME}"
    mkdir "${1}/${SERVER_DIRNAME}"
    mkdir "${1}/${CLIENT_DIRNAME}"
    mkdir "${1}/${HOST_DIRNAME}"
    mkdir "${1}/${CSIGN_DIRNAME}"
    mkdir "${1}/${SMIME_DIRNAME}"
    
    # Create Index + Serial file
    echo "01" > "${1}/${CA_DIRNAME}/serial"
    touch "${1}/${CA_DIRNAME}/db.txt"
    touch "${1}/${CA_DIRNAME}/db.txt.attr"
}
