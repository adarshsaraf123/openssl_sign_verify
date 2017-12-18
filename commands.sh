# to generate the private key
# explore the particular curve to be used; for now this too seems to be okay
openssl ecparam -name prime256v1 -genkey -param_enc explicit -out private_key.pem

# to generate the public key given the private key
openssl ec -in private_key.pem -pubout -out public_key.pem

# to view the private key
# 	-- looks like it generates the public key as well from the private key while viewing
openssl ec -in private_key.pem -text -noout

# to sign a file
openssl dgst -sha256 -sign private_key.pem data.txt > signature.bin

# to verify a signature signed as above
openssl dgst -sha256 -verify public_key.pem -signature signature.bin data.txt

# the signatures are in binary format; 
# get the text format using base64 encoding/decoding
# base64 signature.bin > signature.txt
# back to binary using `base64 -d`; openssl will understand binary 
