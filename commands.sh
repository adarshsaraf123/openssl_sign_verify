# to generate the private key
# TODO: explore the particular curve to be used; for now this too seems to be okay
openssl ecparam -name prime256v1 -genkey -param_enc explicit -out private_key.pem

# encrypt the generated private key; there does not seem to be a built-in option 
#	for the same in ecparam
	# openssl ec -in private_key.pem -out private_key_encrypted.pem -aes256
# the above step for encryption can also be piped to prevent the private key
#	from being return out to the file system unencrypted

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

# to generate a new self-signed certificate
# NOTE: -x509 option specifies that this is a self-signed certificate 
# 	and not a certificate signing request (CSR)
#		-days also applies only for -x509
	# openssl req -new -x509 -key private_key.pem -out server.pem -days 730

# to generate the public key in DER format
	# openssl x509 -outform der -in server.pem -out public_key.der
