#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

const char *private_key_file = "private_key.pem";
const char *public_key_file = "public_key.pem";
const char *data_file = "data.txt";
const char *signature_file = "signature.bin";

int main() {
	BIO *stdout_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	
	// initialize openssl
	OpenSSL_add_all_algorithms();

	// load the private key
	FILE *fp = fopen(private_key_file,"r");
	if (fp == NULL) {
		perror("private key file opening failed");
		exit(1);
	}
	EVP_PKEY *priv_key = PEM_read_PrivateKey(fp, NULL, NULL, (char *) "");
	fclose(fp);
	if (priv_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	// load the public key
	fp = fopen(public_key_file,"r");
	if (fp == NULL) {
		perror("public key file opening failed");
		exit(1);
	}
	EVP_PKEY *pub_key = PEM_read_PUBKEY(fp, NULL, NULL, (char *) "");
	fclose(fp);
	if (pub_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	/*
	else { 
		printf("successfully loaded the private key\n");
	}
	*/	

	// VERIFY SIGNATURE
	
	// 1. Create and initialize the context for the message digest
	EVP_MD_CTX *mdctx = NULL;
	if( ! (mdctx = EVP_MD_CTX_create()) ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	// 2. Read the data file into a string
	fp = fopen(data_file, "r");
	if (fp == NULL) {
		perror("data file opening failed");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	size_t msglen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char * msg = (char *)malloc(msglen + 1); // +1 for the trailing '\0' to be added
	fread(msg, msglen, 1, fp);
	msg[msglen] = '\0';	
	printf("msg: %s\n", msg);
	fclose(fp);

	// 3. Read the cli generated signature file into a string
	fp = fopen(signature_file, "rb");
	if (fp == NULL) {
		perror("data file opening failed");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	size_t cli_siglen = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char * cli_signature = (char *)malloc(cli_siglen + 1); // +1 for the trailing '\0' to be added
	fread(cli_signature, cli_siglen, 1, fp);
	cli_signature[cli_siglen] = '\0';	
	fclose(fp);

	// 4. Sign the message
	size_t generated_siglen;
	// 4a. Init the signing context with sha256 as the digest function
	if( EVP_DigestSignInit( mdctx, NULL, EVP_sha256(), NULL, priv_key ) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// 4b. Update the signing context with the msg
	if( EVP_DigestSignUpdate( mdctx, msg, msglen ) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// 4c. Obtain the max length of the signature that can be generated
	if( EVP_DigestSignFinal( mdctx, NULL, &generated_siglen ) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	char * generated_sign = (char *) malloc(generated_siglen);
	// 4d. Finalize the signing context with the signature
	if( EVP_DigestSignFinal( mdctx, generated_sign, &generated_siglen) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// 4e. Compare the generated signature with the cli signature
	if(strcmp(cli_signature, generated_sign) == 0) {
		printf("generated signature matches cli signature\n");
	}
	else
		printf("generated signature does not match cli signature\n");

	// 5. Verify the signature
	char *signature = cli_signature;
	size_t siglen = cli_siglen;
	// 5a. Init the signature verification context with sha256 as the digest function
	if( EVP_DigestVerifyInit( mdctx, NULL, EVP_sha256(), NULL, pub_key ) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// 5b. Update the signature verification context with the msg
	if( EVP_DigestVerifyUpdate( mdctx, msg, msglen ) != 1 ) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	// 5c. Finalize the signature verification context with the signature
	if( EVP_DigestVerifyFinal( mdctx, signature, siglen ) == 1 ) {
		printf("Verified OK.\n");
	}
	else {
		printf("Verification failed. \n");
		ERR_print_errors_fp(stderr);
	}

	return 0;
}
