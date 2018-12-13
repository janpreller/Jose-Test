package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	uuid "github.com/satori/go.uuid"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func main() {
	loadKeys()
	rawJWT := generateSignedJWT()
	fmt.Println("RAW:", rawJWT)
	encryptedJWT := encryptJWT(rawJWT)
	fmt.Println("ENCRYPTED", encryptedJWT)
	decryptedJWT := decryptJWT(encryptedJWT)
	verifySignature(decryptedJWT)
}

func loadKeys() {
	b, err := ioutil.ReadFile("privkey.pem")
	if err != nil {
		log.Fatalf("could not read private key: %+v", err)
	}

	block, _ := pem.Decode(b)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	privateKey = key
	publicKey = &privateKey.PublicKey
}

func generateSignedJWT() string {
	key := jose.SigningKey{Algorithm: jose.RS512, Key: privateKey}
	rsaSigner, err := jose.NewSigner(key, nil)
	if err != nil {
		log.Fatalf("faled to create signer: %+v", err)
	}

	builder := jwt.Signed(rsaSigner)

	claims := jwt.Claims{
		Audience:  jwt.Audience{"Audience"},
		Expiry:    jwt.NewNumericDate(time.Now()),
		ID:        uuid.Must(uuid.NewV4()).String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "http://localhost",
		NotBefore: jwt.NewNumericDate(time.Now().Add(time.Minute * 1)),
		Subject:   "Subject",
	}

	builder = builder.Claims(claims)

	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT:%+v", err)
	}
	//	fmt.Println(rawJWT)

	return rawJWT
}
func verifySignature(jwt string) {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		log.Fatalf("could not verify signature:%+v", err)
	}
	out, err := object.Verify(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}

func encryptJWT(jwt string) string {
	encOptions := &jose.EncrypterOptions{
		Compression: jose.NONE,
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: publicKey}, encOptions)
	if err != nil {
		log.Fatalf("could not create encrypter:%+v", err)
	}
	object, err := encrypter.Encrypt([]byte(jwt))
	if err != nil {
		log.Fatalf("could not encrypt jwt:%+v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		log.Fatalf("could not serialize jwt:%+v", err)
	}
	return serialized
}

func decryptJWT(encryptedJWT string) string {
	object, err := jose.ParseEncrypted(encryptedJWT)
	if err != nil {
		log.Fatal(err)
	}
	t, err := object.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}
	return string(t)
}
