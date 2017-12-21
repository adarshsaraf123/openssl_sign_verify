#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define DEBUG 0

const char *private_key_file = "private_key.pem";
const char *public_key_file = "public_key.pem";
const char *data_file = "data.txt";
const char *signature_file = "signature.bin";

int read_text_file_to_string(char **str, const char *filename);
int read_binary_file_to_string(unsigned char **str, size_t *length, const char *filename);
int sign_message(const char *msg, unsigned char **signature, size_t *slen, EVP_PKEY *priv_key);
int verify_signature(const char *msg, const unsigned char *signature, const size_t slen, EVP_PKEY *pub_key);

int main() {
	FILE *fp;
	EVP_PKEY *priv_key, *pub_key;
	char *msg;
	unsigned char *signature, *cli_signature, *generated_signature;
	size_t msglen, siglen, cli_siglen, generated_siglen;

	// initialize openssl
	OpenSSL_add_all_algorithms();

	// load the private key
	fp = fopen(private_key_file,"r");
	if (fp == NULL) {
		perror("private key file opening failed\n");
		exit(1);
	}
	priv_key = PEM_read_PrivateKey(fp, NULL, NULL, (char *) "");
	fclose(fp);
	if (priv_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
#if DEBUG
	printf("private key successfully loaded.\n");
#endif
	
	// load the public key
	fp = fopen(public_key_file,"r");
	if (fp == NULL) {
		perror("public key file opening failed\n");
		exit(1);
	}
	pub_key = PEM_read_PUBKEY(fp, NULL, NULL, (char *) "");
	fclose(fp);
	if (pub_key == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
#if DEBUG
	printf("public key successfully loaded\n");
#endif
	
	// Read the data file into a string
	if( !read_text_file_to_string(&msg, data_file) ) {
		perror("data file opening failed\n");
		exit(1);
	}
#if DEBUG
	printf("data file successfully read\n");
#endif

	// Read the cli generated signature file into a string
	if( !read_binary_file_to_string(&cli_signature, &cli_siglen, signature_file) ) {
		perror("signature file opening failed\n");
		exit(1);
	}
	// Sign the message
	if( ! sign_message(msg, &generated_signature, &generated_siglen, priv_key) ) {
		printf("Message signing failed\n");
		ERR_print_errors_fp(stderr);
	}

	// Verify the cli signature
	if ( verify_signature(msg, cli_signature, cli_siglen, pub_key) ) {
		printf("Verified cli signature OK.\n");
	}
	else {
		printf("Verified cli signature NOT OK.\n");
		ERR_print_errors_fp(stderr);
	}

	// Verify the generated signature
	if ( verify_signature(msg, generated_signature, generated_siglen, pub_key) ) {
		printf("Verified generated signature OK.\n");
	}
	else {
		printf("Verified generated signature NOT OK.\n");
		ERR_print_errors_fp(stderr);
	}
	
	return 0;
}

/*
 * Read the given text file into the given string pointer
 * 	Memory will be allocated for the string based on the file size
 * 	The string will be null-terminated
 * Returns 1 on success and 0 on failure
 */
int read_text_file_to_string(char **str, const char *filename) {
	FILE *fp;
	size_t filelen;
	
	// open the file
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return 0;
	}

	// find out the file length
	fseek(fp, 0, SEEK_END);
	filelen = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// allocate memory for the string
	*str = (char *)malloc(filelen + 1); // +1 for the trailing '\0' to be added
	
	// read from file into the string
	fread(*str, filelen, 1, fp);
	// null-terminate the file
	(*str)[filelen] = '\0';	

	// close the file
	fclose(fp);
	return 1;
}

/*
 * Read the given binary file into the given string pointer
 * 	Memory will be allocated for the string based on the file size
 *	The file size will then be set in the length variable
 *
 * Note: being a bytes array it is not null-terminated since zero byte might
 *		appear in the array as well; therefore methods like strlen will 
 *		not work and the length variable should be used
 * Returns 1 on success and 0 on failure
 */
int read_binary_file_to_string(unsigned char **str, size_t *length, const char *filename) {
	FILE *fp;
	
	// open the file
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return 0;
	}

	// find out the file length
	fseek(fp, 0, SEEK_END);
	*length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// allocate memory for the string
	*str = (char *)malloc(*length); // +1 for the trailing '\0' to be added
	
	// read from file into the string
	fread(*str, *length, 1, fp);

	// close the file
	fclose(fp);
	return 1;
}

/*
 * To sign a message given the msg and the private key of the signer
 * Return 1 on success and 0 on failure
 *  Upon failure, print the error encountered using the openssl ERR_ functions
 */
int sign_message(const char *msg, unsigned char **signature, size_t *slen, EVP_PKEY *priv_key) {
	EVP_MD_CTX *mdctx;
	size_t msglen;

	msglen = strlen(msg);

	// 1. Create and initialize the context for the message digest
	mdctx = NULL;
	if( ! (mdctx = EVP_MD_CTX_create()) ) {
		return 0;
	}
	
	// 2. Init the signing context with sha256 as the digest function
	if( EVP_DigestSignInit( mdctx, NULL, EVP_sha256(), NULL, priv_key ) != 1 ) {
		return 0;
	}
	// 3. Update the signing context with the msg
	if( EVP_DigestSignUpdate( mdctx, msg, msglen ) != 1 ) {
		return 0;
	}
	// 4. Obtain the max length of the signature that can be generated
	if( EVP_DigestSignFinal( mdctx, NULL, slen ) != 1 ) {
		return 0;
	}
	*signature = (char *) malloc(*slen);
	// 5. Finalize the signing context with the signature
	if( EVP_DigestSignFinal( mdctx, *signature, slen) != 1 ) {
		return 0;
	}

	// 6. Cleanup
	if(mdctx) 
		EVP_MD_CTX_destroy(mdctx);

	return 1;	
}

/*
 * To verify the signature on a message given the msg, signature and the public key of the signer
 * Return 1 on success and 0 on failure
 *  Upon failure, print the error encountered using the openssl ERR_ functions
 */
int verify_signature(const char *msg, const unsigned char *signature, const size_t slen, EVP_PKEY *pub_key) {
	EVP_MD_CTX *mdctx;
	size_t msglen;

	if( !msg || !signature || !pub_key )
		return 0;

	msglen = strlen(msg);

	// 1. Create and initialize the context for the message digest
	mdctx = NULL;
	if( ! (mdctx = EVP_MD_CTX_create()) ) {
		return 0;
	}
	
	// 2. Init the verification context with sha256 as the digest function
	if( EVP_DigestVerifyInit( mdctx, NULL, EVP_sha256(), NULL, pub_key ) != 1 ) {
		return 0;
	}
	// 3. Update the verification context with the msg
	if( EVP_DigestVerifyUpdate( mdctx, msg, msglen ) != 1 ) {
		return 0;
	}
	// 4. Finalize the verification context with the signature
	if( EVP_DigestVerifyFinal( mdctx, signature, slen) != 1 ) {
		return 0;
	}

	// 5. Cleanup
	if(mdctx) 
		EVP_MD_CTX_destroy(mdctx);

	return 1;	
}

