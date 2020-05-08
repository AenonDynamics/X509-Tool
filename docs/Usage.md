Usage + Commands
==========================================

## Available Commands ##

* [init ca](#init-ca)
* [init openvpn](#init-openvpn)
* [client add](#client-add)
* [client revoke](#client-revoke)
* [server add](#server-add)
* [server revoke](#server-revoke)
* [host add](#host-add)
* [host revoke](#host-revoke)
* [show](#view-certificate)
* [verify](#verify-certificate)

We recommend you to install the tool into a **different** directory. This has the advantage that you only have to maintain one installation which is useable for multiple server setups.

#### Example: ####

```raw
/opt/pki-mgmt
   |- server1 (working dir of your first setup)
   |- server2 (working dir of your second setup)
```

## init-ca ##

Create the CA (Crt+Key)

**Command:** `x509-tool init ca <ca-name>`

```raw
Creating Directory Structure..

__________________________________________________________________________

 Initializing CA [myca]
__________________________________________________________________________


__________________________________________________________________________

 Generating CA..
__________________________________________________________________________

Generating a RSA private key
..................++++
..................................................................................................................................++++
writing new private key to 'test/ca/ca.key'
-----

__________________________________________________________________________

 Certificate [test/ca/ca.crt]
__________________________________________________________________________

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            81:e8:d7:09:ee:f0:a9:2e
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = DE, ST = BERLIN, L = BERLIN, O = My Company, OU = OVPN-PKI Testing, CN = CA_myca, emailAddress = pki-test@yourdomain.tld
        Validity
            Not Before: Apr 25 15:38:46 2019 GMT
            Not After : Apr 22 15:38:46 2029 GMT
        Subject: C = DE, ST = BERLIN, L = BERLIN, O = My Company, OU = OVPN-PKI Testing, CN = CA_myca, emailAddress = pki-test@yourdomain.tld
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption

......
```

## init-openvpn ##

Create the CA (Crt+Key), Server (Crt+Key), Diffie-Hellman Parameter and TLS-Auth Key

**Command:** `x509-tool init openvpn <ca-name>`

In your current working dir, just run the following command to create the CA, Server-Cert, TLS-Auth, DH-Params in one step. The generation of the DH-Params will take **some minutes**!

```raw
/opt/pki-mgmt/server1$ x509-tool init openvpn MyCA
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


## client-add ##

Create a new Client Certificate and sign it

**Command:** `x509-tool client add <name>`

```raw
/opt/pki-mgmt/server1$ x509-tool client add user1

__________________________________________________________________________

 Generating Client Cert [user1]
__________________________________________________________________________

Generating a 4096 bit RSA private key
.............................++
............++
writing new private key to ''
-----
Using configuration from openssl.conf
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

## client-revoke ##

Revoke an existing User Certificate and update the Certificate revocation list

**Command:** `x509-tool client revoke <name>`

```raw
/opt/pki-mgmt/server1$ x509-tool client revoke user1

__________________________________________________________________________

 Revoking Client-Cert [user1]..
__________________________________________________________________________

Revoking Certificate 02.
Data Base Updated

```

## server-add ##

Create a new Server Certificate and sign it

**Command:** `x509-tool server add <name>`

```raw
/opt/pki-mgmt/server1$ x509-tool server add myserver

__________________________________________________________________________

Generating Server Cert [myserver]
__________________________________________________________________________

DE
BERLIN
BERLIN
My Company
OVPN-PKI Testing
myserver
pki-test@yourdomain.tld
generating private-key and signing request..
Generating a RSA private key
.....................................................................++++
..................................................................++++
writing new private key to '...'
-----
creating CRT..
Using configuration from 509-tool/openssl.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'DE'
stateOrProvinceName   :ASN.1 12:'BERLIN'
localityName          :ASN.1 12:'BERLIN'
organizationName      :ASN.1 12:'My Company'
organizationalUnitName:ASN.1 12:'OVPN-PKI Testing'
commonName            :ASN.1 12:'myserver'
emailAddress          :IA5STRING:'pki-test@yourdomain.tld'
Certificate is to be certified until Apr 22 15:36:29 2029 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
converting to p12 format..

......
```

## server-revoke ##

Revoke an existing Server Certificate and update the Certificate revocation list

**Command:** `x509-tool server revoke <name>`

```raw
/opt/pki-mgmt/server1$ x509-tool server revoke myserver

__________________________________________________________________________

 Revoking Cert [myserver]..
__________________________________________________________________________

Revoking Certificate 02.
Data Base Updated

```

## View Certificate ##

View the Certificate as human readable text

**Command:** `x509-tool show <filename>`

```raw
/opt/pki-mgmt/server1$ x509-tool show clients/user1/client.crt

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

**Command:** `x509-tool verify <filename>`

#### Example 1 ####

Client Certificate is not revoked and no expired.

```raw
/opt/pki-mgmt/server1$ x509-tool verify clients/user1/client.crt

__________________________________________________________________________

 Verifying Certificate [clients/user1/client.crt]
__________________________________________________________________________

clients/user1/client.crt: OK
```

#### Example 2 ####

Client Certificate is revoked.

```raw
/opt/pki-mgmt/server1$ x509-tool verify clients/user1/client.crt

__________________________________________________________________________

 Verifying Certificate [clients/user1/client.crt]
__________________________________________________________________________

clients/user1/client.crt: C = DE, ST = BREMEN, L = BREMEN, O = Aenon Dynamics, OU = OVPN-PKI Testing, CN = CLIENT-user1, emailAddress = pki-test@aenon-dynamics.com
error 23 at 0 depth lookup:certificate revoked

```
