package main

import (
	"crypto/x509"
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
}
