#!/usr/bin/env bash
# Generates the OCSP and CRL test fixtures used by crates/testls-checks/src
# (ocsp.rs and revocation.rs).
#
# The fixtures are not committed: responses carry the generation time, and the
# tests derive their clock from the generated "good" response. Run this script
# before `cargo test`; set OPENSSL to pick a specific openssl binary (OpenSSL 3
# or later; LibreSSL is not supported).
#
# Usage: scripts/gen-ocsp-fixtures.sh
set -euo pipefail

# Git Bash on Windows would rewrite the "/CN=..." subjects as paths. openssl
# only ever gets relative paths below, and outputs are copied with `cp`.
export MSYS2_ARG_CONV_EXCL='/CN='

openssl=${OPENSSL:-openssl}
# macOS ships LibreSSL as `openssl`; prefer Homebrew's OpenSSL when present.
if [[ -z ${OPENSSL:-} ]] && "$openssl" version | grep -q LibreSSL \
    && command -v brew >/dev/null && [[ -x "$(brew --prefix openssl@3)/bin/openssl" ]]; then
    openssl="$(brew --prefix openssl@3)/bin/openssl"
fi
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/crates/testls-checks/src/testdata"
work="$root/target/ocsp-fixtures"

rm -rf "$work"
mkdir -p "$work" "$out"
cd "$work"

cat > ext.cnf <<'EOF'
[leaf]
basicConstraints=CA:false
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
[muststaple]
basicConstraints=CA:false
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
tlsfeature=status_request
[responder]
basicConstraints=CA:false
extendedKeyUsage=OCSPSigning
[responder_no_sign]
basicConstraints=CA:false
keyUsage=keyEncipherment
extendedKeyUsage=OCSPSigning
[urls]
basicConstraints=CA:false
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
authorityInfoAccess=OCSP;URI:http://ocsp.example.test/,caIssuers;URI:http://ca.example.test/ca.der
crlDistributionPoints=URI:http://crl.example.test/ca.crl,URI:ldap://crl.example.test/ca
EOF

cat > ca.cnf <<'EOF'
[ca]
default_ca=test_ca
[test_ca]
database=index.txt
crlnumber=crlnumber
default_md=sha256
default_crl_days=7
EOF

# key NAME: writes a P-256 key to NAME.key.
key() {
    "$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null
}

# issue NAME SERIAL SECTION: issues NAME.pem (CN=NAME) from the test CA.
issue() {
    key "$1"
    "$openssl" req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
    "$openssl" x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -set_serial "$2" \
        -days 3650 -sha256 -extfile ext.cnf -extensions "$3" -out "$1.pem" 2>/dev/null
}

# respond CERT SIGNER OUTPUT: writes an OCSP response for CERT signed by SIGNER.
respond() {
    "$openssl" ocsp -issuer ca.pem -sha1 -cert "$1.pem" -reqout "$3.req" -no_nonce 2>/dev/null
    "$openssl" ocsp -index index.txt -CA ca.pem -rsigner "$2.pem" -rkey "$2.key" \
        -reqin "$3.req" -ndays 7 -respout "$3.der" >/dev/null 2>&1
}

key ca
"$openssl" req -x509 -new -key ca.key -subj "/CN=testls OCSP CA" -set_serial 1 \
    -days 3650 -sha256 -addext basicConstraints=critical,CA:true \
    -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem

issue leaf 0x1001 leaf
issue other 0x1002 leaf
issue responder 0x1003 responder
issue stray 0x1004 leaf
issue must-staple 0x1005 muststaple
issue responder-no-sign 0x1006 responder_no_sign
issue urls 0x1007 urls

# Status database: leaf is good, other was revoked for key compromise on
# 2026-10-01; stray is absent and therefore unknown.
printf 'V\t361231000000Z\t\t1001\tunknown\t/CN=leaf\n' > index.txt
printf 'R\t361231000000Z\t261001000000Z,keyCompromise\t1002\tunknown\t/CN=other\n' >> index.txt

respond leaf ca good
respond other ca revoked
respond leaf responder delegated
respond stray responder unknown
respond leaf other unauthorized
respond leaf responder-no-sign no-digital-signature

# CRL from the same database, and one signed by the responder instead of the CA.
echo 1000 > crlnumber
"$openssl" ca -config ca.cnf -gencrl -keyfile ca.key -cert ca.pem -out crl.pem 2>/dev/null
"$openssl" crl -in crl.pem -outform DER -out crl.der
"$openssl" ca -config ca.cnf -gencrl -keyfile responder.key -cert responder.pem \
    -out crl-responder.pem 2>/dev/null
"$openssl" crl -in crl-responder.pem -outform DER -out crl-responder.der

# A correctly signed CRL limited to a different named distribution point.
cat >> ca.cnf <<'EOF'
[partition]
issuingDistributionPoint=critical,@partition_idp
[partition_idp]
fullname=URI:http://crl.example.test/other-partition.crl
EOF
"$openssl" ca -config ca.cnf -gencrl -crlexts partition -keyfile ca.key -cert ca.pem \
    -out crl-partition.pem 2>/dev/null
"$openssl" crl -in crl-partition.pem -outform DER -out crl-partition.der

# The request openssl builds for leaf, to compare with ours.
cp good.req request.der

for cert in ca leaf other stray must-staple urls; do
    "$openssl" x509 -in "$cert.pem" -outform DER -out "$cert.der"
    cp "$cert.der" "$out/ocsp-$cert.der"
done
for response in good revoked delegated unknown unauthorized no-digital-signature \
    crl crl-responder crl-partition request; do
    cp "$response.der" "$out/ocsp-$response.der"
done
echo "wrote OCSP fixtures to $out"
