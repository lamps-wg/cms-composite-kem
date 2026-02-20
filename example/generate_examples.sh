set -e
# set -x

# Needs CryptoNext's build for KEMRecipientInfo and cnsprovider.  Sorry!
PATH=/usr/local/cns_openssl3/bin/:$PATH
EXT_FILE=$(dirname $(realpath $0))/openssl.cnf

openssl pkey -in MLKEM768-ECDH-P256-SHA3-256.priv -pubout -out MLKEM768-ECDH-P256-SHA3-256.pub

##########################################################
# Create mldsa65 root certificate
##########################################################

openssl genpkey -algorithm mldsa65 -out mldsa65RootCA.priv
openssl req -x509 -new -nodes -extensions v3_ca -key mldsa65RootCA.priv -days 3650 \
    -out mldsa65RootCA.pem -subj "/C=PT/ST=Bliss/CN=ML-DSA-65 Root Cert"

##########################################################
# Create Composite ML-KEM EE certificate
##########################################################
openssl genrsa -out fake_rsakey.pem 1024
openssl req -new -key fake_rsakey.pem -out fake_rsa.csr \
    -subj "/C=PT/ST=Bliss/CN=MLKEM768-ECDH-P256-SHA3-256"

# Create KEM certificate from the fake CSR by forcing the KEM key during the certificate creation.
openssl x509 -req -in fake_rsa.csr -extfile $EXT_FILE -extensions v3_ee_kem -CAkey mldsa65RootCA.priv \
    -CA mldsa65RootCA.pem -force_pubkey MLKEM768-ECDH-P256-SHA3-256.pub \
    -outform PEM -out MLKEM768-ECDH-P256-SHA3-256.pem -CAcreateserial
rm fake_rsa.csr
rm fake_rsakey.pem

openssl x509 -in MLKEM768-ECDH-P256-SHA3-256.pem -noout -ext subjectKeyIdentifier | tail -n 1 | tr -d ' :' > MLKEM768-ECDH-P256-SHA3-256.keyid

##########################################################
# Encrypt message
##########################################################
echo -n "Hello, world!" > plaintext.txt

openssl cms -encrypt -in plaintext.txt \
    -outform PEM -out MLKEM768-ECDH-P256-SHA3-256.cms \
    -recip MLKEM768-ECDH-P256-SHA3-256.pem \
    -aes-256-gcm \
    -keyid
openssl cms -cmsout -in MLKEM768-ECDH-P256-SHA3-256.cms -inform PEM -out MLKEM768-ECDH-P256-SHA3-256.cms.der -outform DER

openssl cms -cmsout -in MLKEM768-ECDH-P256-SHA3-256.cms -inform PEM -outform DER -out MLKEM768-ECDH-P256-SHA3-256.cms.der
dumpasn1 -a -i -w64 MLKEM768-ECDH-P256-SHA3-256.cms.der > MLKEM768-ECDH-P256-SHA3-256.cms.txt
rm MLKEM768-ECDH-P256-SHA3-256.cms.der

openssl cms -decrypt -inform PEM -in MLKEM768-ECDH-P256-SHA3-256.cms -recip MLKEM768-ECDH-P256-SHA3-256.pem \
    -inkey MLKEM768-ECDH-P256-SHA3-256.priv -out decrypted.txt

rm -f cek.txt ciphertext.txt encrypted_cek.txt kek.txt ori_info.txt shared_secret.txt

echo "*******************************************"
echo "Examples Generated!"
echo "REMEMBER TO UPDATE INTERMEDIATE ARTIFACTS"
echo "(e.g. cek.txt)  gdb is your friend"
echo "*******************************************"
