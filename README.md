X509 PKI Setup Utility
==========================

Single-File-Utlity to create X509 Certificates/PKI Structure for your OpenVPN Server or **any** TLS based communication.

## Features ##

* Single File CLI Tool
* Create CA, TLS Auth, Server Cert, DH-Params **in one Step**
* Add Clients
* Revoke Clients
* View Certificates
* Verify Certificates
* Maintain Certificate revocation list

## Preface ##

**The X509-Tool is designed as [easy-rsa](https://github.com/OpenVPN/easy-rsa) replacement**

The primary objective is the creation of a simple, bulletproof tool which allows users to setup Certificates for OpenVPN or Webserver/TLS Authentication.
Such tasks doesn't require a bunch of intermdiate CAs or multiple server certificates.

### Basic CA Structure ###

In most cases (e.g. OpenVPN or Webserver Auth) your typical PKI will look like this:

![Demo](assets/structure.png)

* 1 Certificate Authority
* 1 Server 
* 1 to N Clients
* No Intermediate CA
* Cerificate Depths of **1**

### Directoy Structure ###

The **X506-Tool** will create the following directory structure in your working dir

```raw
working-dir
   |- ca (the Cerificate Authority files, database, ..)
   |     |- ca.crt
   |     |- ca.key
   |     |- db.txt (list of all issued/revoked certs)
   |     |- serial (certificate serial number counter)
   |     |- crl.pem (Certificate revocation list)
   |
   |- srv (the Server Certificate, Private Key, TLS Auth Key, DH-Params)
   |     |- server.crt
   |     |- server.key
   |     |- tls-auth.key
   |     |- server.csr
   |     |- dhparam4096.pem
   |
   |- clients (Storage of the Client Certificates)
        |- <client-name-a>
        |- <client-name-b>
            |- client.crt
            |- client.key
            |- client.p12 (Client Cert+Key + CA Cert as single file)
            |- tls-auth.key
            |- client.csr

```

### OpenSSL Configuration ###

The Tool is shipped with a customized `openssl.conf` file which matches the used directory structure as well as client/server handling.
**Do not edit** this file if your are not sure what you're doing!

## Usage ##

### Syntax ###

```raw
Usage: x509-tool.sh init|add-client|revoke-client|show|verify <name/filename>
```

We recommend you to install the tool into a **separate** directory. This has the advantage that you only have to maintain one installation which is useable for multiple server setups.

#### Example: ####

```raw
/opt/pki-mgmt
   |- x509-tool (the downloaded files)
   |- server1 (working dir of your first setup)
   |- server2 (working dir of your second setup)
```

## Initial Setup ##

### Configuration File ###

First of all, you have to create a configuration file name `cert.conf` in your desired **working directory** (/opt/pki-mgmt/server1 in the example above). 
This file contains some basic settings like the keysize, lifetime and certificate informations.

**All Options are required** 

```bash
#!/bin/bash

# Recommended Key Size: >= 3072 bit
export KEY_SIZE=4096

# In how many days should the root CA key expire?
export CA_EXPIRE=3650

# In how many days should certificates expire?
export CRT_EXPIRE=3650

# Your Cert Params
export KEY_COUNTRY="DE"
export KEY_PROVINCE="BREMEN"
export KEY_CITY="BREMEN"
export KEY_ORG="Aenon Dynamics"
export KEY_EMAIL="pki-test@aenon-dynamics.com"
export KEY_OU="OVPN-PKI Testing"
```

### CA, Server-Cert, TLS-Auth, DH-Params ###

**Command:** `x509-tool.sh init <ca-name>`

In your current working dir, just run the following command to create the CA, Server-Cert, TLS-Auth, DH-Params in one step. The generation of the DH-Params will take **some minutes**!

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh init MyCA
Creating Directory Structure..

__________________________________________________________________________

 Initializing CA [MyCA]
__________________________________________________________________________

Generating TLS Auth Key..

__________________________________________________________________________

 Generating CA..
__________________________________________________________________________

Generating a 4096 bit RSA private key
................................................++
..........++
writing new private key to '/opt/pki-mgmt/server1/ca/ca.key'
-----

__________________________________________________________________________

 Certificate [/opt/pki-mgmt/server1/ca/ca.crt]
__________________________________________________________________________

.....

```


## Add Client ##

Create a new Client Certificate and sign it

**Command:** `x509-tool.sh add-client <name>`

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh add-client user1

__________________________________________________________________________

 Generating Client Cert [user1]
__________________________________________________________________________

Generating a 4096 bit RSA private key
.............................++
............++
writing new private key to '/home/andi/Development/OVPN-PKI/test/clients/user1/client.key'
-----
Using configuration from /home/andi/Development/OVPN-PKI/openssl.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'DE'
stateOrProvinceName   :ASN.1 12:'BREMEN'
localityName          :ASN.1 12:'BREMEN'
organizationName      :ASN.1 12:'Aenon Dynamics'
organizationalUnitName:ASN.1 12:'OVPN-PKI Testing'
commonName            :ASN.1 12:'CLIENT-user1'
emailAddress          :IA5STRING:'pki-test@aenon-dynamics.com'
Certificate is to be certified until Jan  5 12:35:45 2027 GMT (3650 days)

......
```

## Revoke Client ##

Revoke an existing User Certificate and update the Certificate revocation list

**Command:** `x509-tool.sh revoke-client <name>`

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh revoke-client user1

__________________________________________________________________________

 Revoking Client-Cert [user1]..
__________________________________________________________________________

Revoking Certificate 02.
Data Base Updated

```

## View Certificate ##

View the Certificate as human readable text

**Command:** `x509-tool.sh show <filename>`

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh show clients/user1/client.crt

__________________________________________________________________________

 Certificate [clients/user1/client.crt]
__________________________________________________________________________

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=DE, ST=BREMEN, L=BREMEN, O=Aenon Dynamics, OU=OVPN-PKI Testing, CN=CA-testca/emailAddress=pki-test@aenon-dynamics.com
        Validity
            Not Before: Jan  7 12:35:45 2017 GMT
            Not After : Jan  5 12:35:45 2027 GMT
        Subject: C=DE, ST=BREMEN, L=BREMEN, O=Aenon Dynamics, OU=OVPN-PKI Testing, CN=CLIENT-user1/emailAddress=pki-test@aenon-dynamics.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
.....
```


## Verify Certificate ##

This command allows you to check the certificate status (lifetime, revocation)

**Command:** `x509-tool.sh verify <filename>`

#### Example 1 ####

Client Certificate is not revoked and no expired.

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh verify clients/user1/client.crt

__________________________________________________________________________

 Verifying Certificate [clients/user1/client.crt]
__________________________________________________________________________

clients/user1/client.crt: OK
```

#### Example 2 ####

Client Certificate is revoked.

```raw
andi@sapphire:/opt/pki-mgmt/server1$ ../x509-tool.sh verify clients/user1/client.crt

__________________________________________________________________________

 Verifying Certificate [clients/user1/client.crt]
__________________________________________________________________________

clients/user1/client.crt: C = DE, ST = BREMEN, L = BREMEN, O = Aenon Dynamics, OU = OVPN-PKI Testing, CN = CLIENT-user1, emailAddress = pki-test@aenon-dynamics.com
error 23 at 0 depth lookup:certificate revoked

```

## Security Recommendations ##

* Keep your **Private Keys secret** - especially the CA Key.
* Consider to **encrypt** your Private Keys by a strong passphrase using AES256

### Ciphers ###

The following ciphers are used by default:

* 4096 Bit [RSA Keys](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* 4096 Bit [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) Parameters
* AES256-CBC Symmetric Packet Encryption (Context: OpenVPN)
* SHA256 Message Digest (Context: OpenVPN)

## Contributing ##
Contributors are welcome! Even if you are not familiar with X509 certificates or bash scripting you can help to improve the documentation!

## Resources ##

A set of useful resources

* [Public key infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure)
* [AES](https://en.wikipedia.org/wiki/<Advanced_Encryption_Standard></Advanced_Encryption_Standard>)
* [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)
* [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html)
* [OpenVPN HOWTO](https://openvpn.net/index.php/open-source/documentation/howto.html)
* [easy-rsa](https://github.com/OpenVPN/easy-rsa)

## License ##
X509-Tool is OpenSource and licensed under the Terms of [The MIT License (X11)](http://opensource.org/licenses/MIT). You're welcome to contribute!