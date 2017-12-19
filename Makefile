generated = private_key.pem public_key.pem signature.bin

openssl_crypto: openssl_crypto.c
	gcc -g openssl_crypto.c -lcrypto -o openssl_crypto

clean:
	rm $(generated) openssl_crypto
