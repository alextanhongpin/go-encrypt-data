package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

// https://security.stackexchange.com/questions/184305/why-would-i-ever-use-aes-256-cbc-if-aes-256-gcm-is-more-secure
// https://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64
// https://medium.com/@badu_bizzle/per-user-encryption-in-elixir-part-i-645f2dfaf8e6
// https://astaxie.gitbooks.io/build-web-application-with-golang/en/09.6.html

// How to implement it with SQL.
// http://jmoiron.net/blog/built-in-interfaces/
func main() {
	// user key: unique key generated for each user on registration. This key will be used to encrypt/decrypt all user's data. It remains unchanged for user.
	userKey, err := generateRandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("userkey: %0x\n", userKey)

	password := []byte("strong password")
	salt, err := generateRandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("salt: %0x\n", salt)
	dk := generatePasswordDerivedKey(password, salt)
	if err != nil {
		log.Fatal(err)
	}
	// password derived key: key generated based on user's password and a unique salt. The unique salt ensure similar password result in different keys.
	// Pass will be saved. password derived key is used to encrypt the user key.
	fmt.Printf("derived key: %0x\n", dk)
	encryptedUserKey, err := encrypt(dk, userKey)
	if err != nil {
		panic(err)
	}

	// Store the keyhash in the database.
	keyHash := make([]byte, len(encryptedUserKey)+len(salt))
	copy(keyHash[:len(encryptedUserKey)], encryptedUserKey)
	copy(keyHash[len(encryptedUserKey):], salt)
	fmt.Printf("keyHash: %0x\n", keyHash)

	derivedKey := generatePasswordDerivedKey(password, keyHash[len(keyHash)-32:])
	decryptedUserKey, err := decrypt(derivedKey, keyHash[:len(keyHash)-32])
	if err != nil {
		log.Fatal("errorDecryptingUserKey", err)
	}
	if ok := bytes.Equal(userKey, decryptedUserKey); !ok {
		log.Fatal("not equal")
	}
	log.Println("userKeylen", len(userKey), len(decryptedUserKey))

	data := []byte("hello world")
	ciphertext, err := encrypt(decryptedUserKey, data)
	if err != nil {
		log.Fatal("errorEncryptingUserKey", err)
	}
	fmt.Printf("ciphertext: %x\n", ciphertext)
	result, err := decrypt(decryptedUserKey, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("result: %s", result)
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, err
}

func generatePasswordDerivedKey(password, salt []byte) []byte {
	// password derived key: key generated based on user's password and a unique salt. The unique salt ensure similar password result in different keys.
	// Pass will be saved. password derived key is used to encrypt the user key.
	return pbkdf2.Key(password, salt, 4096, 32, sha256.New)
}
