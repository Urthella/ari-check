#!/usr/bin/env bash
# Makes the test PKI in test/fixtures: a CA, a localhost certificate whose serial needs a leading
# zero byte in DER, and one without an Authority Key Identifier. The keys are for tests only.
set -euo pipefail
cd "$(dirname "$0")/../test/fixtures"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -subj "/O=ari-check test CA/CN=Test Root" -days 3650 -out ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out localhost.key
openssl req -new -key localhost.key -subj "/CN=localhost" -out localhost.csr
printf 'subjectAltName=DNS:localhost\nauthorityKeyIdentifier=keyid\n' > with-aki.ext
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -set_serial 0x87654321abcdef -days 3650 \
  -extfile with-aki.ext -out localhost.pem
printf 'subjectAltName=DNS:localhost\nauthorityKeyIdentifier=none\nsubjectKeyIdentifier=none\n' > no-aki.ext
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -set_serial 0x1234 -days 3650 \
  -extfile no-aki.ext -out no-aki.pem
# Valid only in January 2025, so the CA must never be asked about it.
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -set_serial 0x42 \
  -not_before 20250101000000Z -not_after 20250201000000Z -extfile with-aki.ext -out expired.pem
# Version 1: no version field before the serial, and no extensions. A config of its own keeps
# the default one from adding v3 extensions.
printf '[req]\ndistinguished_name = dn\n[dn]\n' > v1.cnf
openssl req -x509 -x509v1 -config v1.cnf -key localhost.key -subj "/CN=v1" -days 3650 -out v1.pem
rm localhost.csr with-aki.ext no-aki.ext v1.cnf
