package main

import (
	"crypto"
	"crypto/x509"
	_ "crypto/sha256"
	// _ "crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func panic_on_error(err error) {
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
}

func main() {
	keyPemBytes, err := ioutil.ReadFile("private_key.pem")
	panic_on_error(err)
	// first pem block is the ec parameters
	pemBlock, remainingBytes := pem.Decode([]byte(keyPemBytes))
	// this block is the actual private key
	pemBlock, _ = pem.Decode(remainingBytes)
	fmt.Println(pemBlock.Type, pemBlock.Headers, pemBlock.Bytes)
	// fmt.Print(pemBlock)
	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	panic_on_error(err)
	fmt.Print(privateKey)

	// obtain the digest
	message, err := ioutil.ReadFile("data.txt")
	hashfunc := crypto.SHA256
	h := hashfunc.New()
	h.Write(message)
	digest := h.Sum(nil)

	// sign the digest
	signature, err := privateKey.Sign(rand.Reader, digest, hashfunc)

	fmt.Print(signature)
	err = ioutil.WriteFile("signature.bin", signature, 0666)
	panic_on_error(err)
}
