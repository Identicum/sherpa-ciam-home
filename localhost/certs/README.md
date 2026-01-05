# Self-signed certificates para IDP localhost

```sh

# create private key
openssl genrsa -out localhost_idsherpa.key -passout file:passphrase.txt 2048

# create csr
openssl req -new -key localhost_idsherpa.key -out localhost_idsherpa.csr -config localhost_idsherpa.conf

# sign cert
openssl x509 -req -days 3650 -in localhost_idsherpa.csr -signkey localhost_idsherpa.key -out localhost_idsherpa.crt -extensions req_ext -extfile localhost_idsherpa.conf
```