#!/bin/bash

FILENAME=firmware.hex
FILE_SIZE=6144

# generate secret and public certificate for perfoming
# file validation
openssl req -x509 -nodes -sha256 -newkey rsa:4096 -keyout "secret.pem" -subj '//C=US//ST=Oregon//L=Portland//CN=www.example.com' -out "public.pem"

# generate a test file (6K)
python file_gen.py $FILENAME $FILE_SIZE

# sign the test file with secret key
openssl dgst -sha256 -sign "secret.pem" -out $FILENAME.sha256 $FILENAME 
