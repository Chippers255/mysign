package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func rsaConfigSetup(rsaPrivateKeyLocation, rsaPrivateKeyPassword string) (*rsa.PrivateKey, error) {
	if rsaPrivateKeyLocation == "" {
		fmt.Println("no RSA Key given, generating temp one")
		return GenRSA(4096)
	}

	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		fmt.Println("no RSA private key found, generating temp one")
		return GenRSA(4096)
	}

	privPem, _ := pem.Decode(priv)
	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		fmt.Println("RSA private key is of the wrong type")
		fmt.Println(privPem.Type)
	}

	if rsaPrivateKeyPassword != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivateKeyPassword))
	} else {
		privPemBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			fmt.Println("Unable to parse RSA private key, generating a temp one")
			fmt.Println(err)
			return GenRSA(4096)
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("Unable to parse RSA private key, generating a temp one")
		fmt.Println(err)
		return GenRSA(4096)
	}

	// pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	// if err != nil {
	// 	fmt.Println("No RSA public key found, generating temp one", nil)
	// 	return GenRSA(4096)
	// }
	// pubPem, _ := pem.Decode(pub)
	// if pubPem == nil {
	// 	fmt.Println("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key")
	// 	fmt.Println("rsa public key not in pem format")
	// 	fmt.Println(rsaPublicKeyLocation)
	// 	return GenRSA(4096)
	// }
	// if pubPem.Type != "RSA PUBLIC KEY" {
	// 	fmt.Println("RSA public key is of the wrong type")
	// 	fmt.Println(pubPem.Type)
	// 	return GenRSA(4096)
	// }

	// if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
	// 	fmt.Println("Unable to parse RSA public key, generating a temp one")
	// 	fmt.Println(err)
	// 	return GenRSA(4096)
	// }

	// var pubKey *rsa.PublicKey
	// if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
	// 	fmt.Println("Unable to parse RSA public key, generating a temp one")
	// 	fmt.Println(err)
	// 	return GenRSA(4096)
	// }

	//privateKey.PublicKey = pubKey

	return privateKey, nil
}

// GenRSA returns a new RSA key of bits length
func GenRSA(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	fmt.Println("Failed to generate signing key")
	fmt.Println(err)
	return key, err
}

func main() {
	privateKey, err := rsaConfigSetup("home/tomos/.ssh/id_rsa", "")
	if err != nil {
		panic(err)
	}

	signedMsg := "Yo, this message is approved by Tomos."
	//unsignedMsg := "This message is not Tomos approved."

	signedHash := md5.Sum([]byte(signedMsg))
	//unsignedHash := md5.Sum([]byte(unsignedMsg))

	//message := []byte("message to be signed")
	//hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, signedHash[:])
	if err != nil {
		panic(err)
	}

	fmt.Println(signedHash)
	fmt.Println(signature)
	fmt.Printf("signed hash: %s", signedHash)
}
