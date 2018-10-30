package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type KeyHash struct {
	Digest     string
	Hash       []byte
	Iter       int
	Salt       []byte
	EncUserKey []byte
	KeyLen     int
}

func (k *KeyHash) String() string {
	return fmt.Sprintf(`$pbkdf2-%s$i=%d$%s$%s$%s`, k.Digest, k.Iter, base64.StdEncoding.EncodeToString(k.Salt), base64.StdEncoding.EncodeToString(k.Hash), base64.StdEncoding.EncodeToString(k.EncUserKey))
}

func (k *KeyHash) From(str string) (err error) {
	data := strings.Split(str, "$")
	digestRaw := strings.Split(data[1], "-")
	k.Digest = digestRaw[1]
	iterRaw := strings.Split(data[2], "=")
	k.Iter, err = strconv.Atoi(iterRaw[1])
	if err != nil {
		return err
	}
	k.Salt, err = base64.StdEncoding.DecodeString(data[3])
	if err != nil {
		return err
	}
	k.Hash, err = base64.StdEncoding.DecodeString(data[4])
	if err != nil {
		return err
	}
	k.EncUserKey, err = base64.StdEncoding.DecodeString(data[5])
	return err
}

func (k *KeyHash) DecodeUserKey(password []byte) ([]byte, error) {
	hash := pbkdf2.Key(password, k.Salt, k.Iter, k.KeyLen, sha256.New)
	return decrypt(hash, k.EncUserKey)
}

// https://coolaj86.com/articles/symmetric-cryptography-aes-with-webcrypto-and-node-js/
// https://gist.github.com/AndiDittrich/4629e7db04819244e843
// https://jg.gg/2018/01/22/communicating-via-aes-256-gcm-between-nodejs-and-golang/
// https://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage
func main() {
	password := []byte("super strong password")
	keyHash, err := generateKeyHash(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("keyHash", keyHash)

	userKey, err := keyHash.DecodeUserKey(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("userKey %x\n", userKey)
	encryptedData, err := encrypt(userKey, []byte("hello world!"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("encrypted data: %x\n", encryptedData)
	if err != nil {
		log.Fatal(err)
	}
	decryptedData, err := decrypt(userKey, encryptedData)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("decrypted data: %s\n", decryptedData)
}

// randomBytes generate a random bytes of given size.
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
	// In node.js, this is called IV.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	log.Printf("encrypt nonce: %x\n", nonce)
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

// generateKeyHash that will be stored in the database. This will contain the
// user key that is required to encrypt/decrypt the data and the user key can
// only be unlocked from the user's password.
func generateKeyHash(password []byte) (*KeyHash, error) {
	// Generate a unique user key for each new user. This key
	// will be used to encrypt/decrypt all data. User key remains unchanged
	// for a user.
	userKey, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	// Generate a unique salt to hash the password. This is required so that the same password will result in different salt.
	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	iter := 100000
	keyLen := 32
	digest := "sha256"
	// Password-derived key is generated from the password and a unique salt.
	// The unique salt ensure that similar password results in different key.
	// The password-derived key is used to encrypt the userkey.
	hash := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	encUserKey, err := encrypt(hash, userKey)
	if err != nil {
		return nil, err
	}
	return &KeyHash{
		Salt:       salt,
		Iter:       iter,
		Digest:     digest,
		Hash:       hash,
		KeyLen:     keyLen,
		EncUserKey: encUserKey,
	}, nil
}
