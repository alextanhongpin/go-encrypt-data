package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// https://coolaj86.com/articles/symmetric-cryptography-aes-with-webcrypto-and-node-js/
// https://gist.github.com/AndiDittrich/4629e7db04819244e843
// https://jg.gg/2018/01/22/communicating-via-aes-256-gcm-between-nodejs-and-golang/
// https://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage
func main() {

	// Step 1: Generate a unique user key for each new user. This key
	// will be used to encrypt/decrypt all data. User key remains unchanged
	// for a user.
	userkey, err := randomBytes(32)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("userkey: %x\n", userkey)

	// Step 2: Password-derived key is generated from the password and a unique salt.
	// The unique salt ensure that similar password results in different key.
	// The password-derived key is used to encrypt the userkey.
	salt, err := randomBytes(32)
	if err != nil {
		log.Println(err)
	}
	fmt.Printf("salt: %x\n", salt)

	iter := 4096
	keyLen := 32
	password := []byte("hello world")

	passwordDerivedKey := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	fmt.Printf("password derived key: %x\n", passwordDerivedKey)
	phcPbkdf2 := fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s",
		"sha256", // digest
		iter,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(passwordDerivedKey))
	fmt.Println(phcPbkdf2)

	encryptedUserkey, err := encrypt(passwordDerivedKey, userkey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encryptedUserkey: %s\n", base64.StdEncoding.EncodeToString(encryptedUserkey))

	// We will store the following in the database.
	keyhash := fmt.Sprintf("%s$%s", base64.StdEncoding.EncodeToString(encryptedUserkey), base64.StdEncoding.EncodeToString(salt))
	fmt.Printf("keyhash: %s\n", keyhash)

	// Deriving the userkey back from the keyhash.
	output := strings.Split(keyhash, "$")
	encryptedUserKey2, err := base64.StdEncoding.DecodeString(output[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("encryptedUserKey2: %x\n", encryptedUserKey2)
	salt2, err := base64.StdEncoding.DecodeString(output[1])
	if err != nil {
		log.Fatal(err)
	}
	log.Println("salt2 orig", output[1])
	log.Printf("salt2: %x\n", salt2)
	passwordDerivedKey2 := pbkdf2.Key(password, salt2, iter, keyLen, sha256.New)
	log.Printf("password derived key: %x\n", passwordDerivedKey2)
	decryptedUserkey, err := decrypt(passwordDerivedKey2, encryptedUserKey2)
	if err != nil {
		log.Fatal("error decrypting:", err)
	}
	fmt.Println("encrypted and decrypted user key equal", bytes.Equal(decryptedUserkey, userkey))

	// Encrypting data.
	encryptedData, err := encrypt(decryptedUserkey, []byte("hello world!"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encrypted data: %x\n", encryptedData)
	fmt.Printf("encrypted data: %s\n", base64.StdEncoding.EncodeToString(encryptedData))

	// Decrypting data.

	decryptedData, err := decrypt(decryptedUserkey, encryptedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decrypted data: %s\n", decryptedData)
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	return buf, err
}

func encrypt(passphrase, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(passphrase)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// nonce := make([]byte, gcm.NonceSize())
	// if _, err := rand.Read(nonce); err != nil {
	//         return nil, err
	// }
	nonce, _ := hex.DecodeString("7741908cc94a83bc4abcee88")
	// Prepend the nonce to the encrypted data.
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(passphrase, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(passphrase)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
