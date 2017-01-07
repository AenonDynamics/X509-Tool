#!/usr/bin/env bash

# Exit on Error
set -e

# CLI Usage
USAGE_INFO="Usage: x509-tool.sh init|add-client|revoke-client|show|verify <name>"

# current working dir
WORKING_DIR="$(pwd)"

# basedir
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# locations
OVPN_BIN=/usr/sbin/openvpn
OPENSSL_BIN=/usr/bin/openssl

# action given ?
if [ $# -ne 2 ]; then
    echo $USAGE_INFO
    exit 1
fi

# name provided ?
if [ -z "$2" ]; then
    echo $USAGE_INFO
    exit 1
fi

# cert config available ?
if [ ! -f "$WORKING_DIR/cert.conf" ]; then
    echo "Error: Configuration file cert.conf not found in current directory! Do you have created it yet?"
    exit 1
fi

# Load cert config/parameter
source "$WORKING_DIR/cert.conf"

# VARS
# ----------------------------------------------

# Export Config Dirs
export CA_DIR="$WORKING_DIR/ca"
export SRV_DIR="$WORKING_DIR/srv"
export CLIENT_DIR="$WORKING_DIR/clients"

# client CN, server CN and CA Name templates
CA_NAME="CA-$2"
SRV_NAME="SRV-$2"
CLIENT_NAME="CLIENT-$2"

# Simple Header
# ----------------------------------------------
print_heading(){
    if [ $# -ne 1 ]; then
        return 1
    fi

    # blue
    echo -e '\x1B[1;34m'
    echo "__________________________________________________________________________"
    echo ""
    echo " $1"
    echo "__________________________________________________________________________"
    echo -e '\x1B[39m'
}

# Display Cert in clear-text
# ----------------------------------------------
function showCert(){
    print_heading "Certificate [$1]"
    $OPENSSL_BIN x509 -in $1 -text -noout
}

# (Re-)Create the Certificate revocation list
# ----------------------------------------------
function createCRL(){
    print_heading "Certificate revocation list [$1]"
    $OPENSSL_BIN ca -batch -gencrl -config $BASEDIR/openssl.conf -out $CA_DIR/crl.pem
    $OPENSSL_BIN crl -in $CA_DIR/crl.pem -noout -text

    # join ca+crl for verification
    cat $CA_DIR/crl.pem $CA_DIR/ca.crt > $CA_DIR/ca-crl-verify.pem
}

# Verifying Cert including Certificate revocation list
# ----------------------------------------------
function verifyCert(){
    print_heading "Verifying Certificate [$1]"
    $OPENSSL_BIN verify -crl_check -CAfile $CA_DIR/ca-crl-verify.pem $1
}

# Create CA, Server Cert, TLS Auth Key, dhparams
# ----------------------------------------------
function init(){
    # directory already exists ?
    if [ -d "$CA_DIR" ] || [ -d "$SRV_DIR" ]; then
        echo "Configuration $1 already exists!"
        exit 1
    else
        # create config dir
        echo "Creating Directory Structure.."
        mkdir $CA_DIR
        mkdir $SRV_DIR
        mkdir $CLIENT_DIR
    fi

    print_heading "Initializing CA [$1]"

    # HMAC auth key setup
    echo "Generating TLS Auth Key.."
    $OVPN_BIN --genkey --secret $SRV_DIR/tls-auth.key

    # Set Common Name
    export KEY_CN="$CA_NAME"

    # Create Index +  Serial file
    echo "01" > "$CA_DIR/serial"
    touch "$CA_DIR/db.txt"

    # Create CA
    print_heading "Generating CA.."
    $OPENSSL_BIN req -days $CA_EXPIRE -nodes -new -x509 -keyout $CA_DIR/ca.key -out $CA_DIR/ca.crt -config $BASEDIR/openssl.conf

    # show CA cert
    showCert $CA_DIR/ca.crt

    # Create CRL
    createCRL

    # Set Common Name
    export KEY_CN="$SRV_NAME"

    # Create Private Key + CSR
    print_heading "Generating Server Cert.."
    $OPENSSL_BIN req -days $CRT_EXPIRE -nodes -new -keyout $SRV_DIR/server.key -out $SRV_DIR/server.csr -config $BASEDIR/openssl.conf
    $OPENSSL_BIN ca -batch -extensions server -days $SRV_DIR -out $SRV_DIR/server.crt -in $SRV_DIR/server.csr -config $BASEDIR/openssl.conf

    # show server cert
    showCert $SRV_DIR/server.crt

    # Diffie hellman parameters
    print_heading "Generating DHParams"
    echo "Even Modern Systems (XEON/Core i) will take around 10-40min to complete!"
    $OPENSSL_BIN dhparam -out $SRV_DIR/dh$KEY_SIZE.pem $KEY_SIZE

    # success!
    print_heading "READY!"
}

# Create new Client CRT
# ----------------------------------------------
function addClient(){
    # client not exists ?
    if [ -s "$CLIENT_DIR/$1/client.crt" ]; then
        echo "Client Configuration [$1] already exists!"
        exit 1
    fi

    print_heading "Generating Client Cert [$1]"

    # create client dir
    mkdir -p $CLIENT_DIR/$1

    # Set Clients Common Name
    export KEY_CN="$CLIENT_NAME"

    # Create Private Key + CSR
    $OPENSSL_BIN req -days $CRT_EXPIRE -nodes -new -keyout $CLIENT_DIR/$1/client.key -out $CLIENT_DIR/$1/client.csr -config $BASEDIR/openssl.conf

    # Sign CSR -> Generate CERT
    $OPENSSL_BIN ca -batch -extensions usr_cert -days $CRT_EXPIRE -out $CLIENT_DIR/$1/client.crt -in $CLIENT_DIR/$1/client.csr -config $BASEDIR/openssl.conf

    # Convert to p12 (easier handling)
    $OPENSSL_BIN pkcs12 -nodes -export -out $CLIENT_DIR/$1/client.p12 -inkey $CLIENT_DIR/$1/client.key -in $CLIENT_DIR/$1/client.crt -certfile $CA_DIR/ca.crt

    # Copy TLS Auth
    cp $SRV_DIR/tls-auth.key $CLIENT_DIR/$1/tls-auth.key

    # show cert
    showCert $CLIENT_DIR/$1/client.crt
}

# Revoke existing Client CRT
# ----------------------------------------------
function revokeClient(){
    # client not exists ?
    if [ ! -f "$CLIENT_DIR/$1/client.crt" ]; then
        echo "Client Configuration [$1] not exists!"
        exit 1
    fi

    # Set Clients Common Name
    export KEY_CN="$CLIENT_NAME"

    print_heading "Revoking Client-Cert [$1].."
    $OPENSSL_BIN ca -revoke $CLIENT_DIR/$1/client.crt -config $BASEDIR/openssl.conf

    # Re-Create CRL
    createCRL
}

# Command Dispatching
# ---------------------------------------
case "$1" in
    init)
        init $2
        exit 0
    ;;

    add-client)
        addClient $2
        exit 0
    ;;

    revoke-client)
        revokeClient $2
        exit 0
    ;;

    show)
        showCert $2
        exit 0
    ;;

    verify)
        verifyCert $2
        exit 0
    ;;

    *)
        echo "$USAGE_INFO"
        exit 1
    ;;
esac