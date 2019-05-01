package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"

	"github.com/jansemmelink/log"
)

//CreateHash ...
func CreateHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

//Encrypt ...
func Encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(CreateHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

//Decrypt ...
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(CreateHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, log.Wrapf(err, "Failed to create cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, log.Wrapf(err, "Failed to create new GCM")
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, log.Wrapf(err, "Failed to open")
	}
	return plaintext, nil
}

//EncryptFile ...
func EncryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(Encrypt(data, passphrase))
}

//DecryptFile ...
func DecryptFile(filename string, passphrase string) ([]byte, error) {
	data, _ := ioutil.ReadFile(filename)
	data, err := Decrypt(data, passphrase)
	if err != nil {
		return nil, log.Wrapf(err, "Failed to decrypt")
	}
	return data, nil
}

// func main() {
// 	fmt.Println("Starting the application...")
// 	ciphertext := encrypt([]byte("Hello World"), "password")
// 	fmt.Printf("Encrypted: %x\n", ciphertext)
// 	plaintext := decrypt(ciphertext, "password")
// 	fmt.Printf("Decrypted: %s\n", plaintext)
// 	encryptFile("sample.txt", []byte("Hello World"), "password1")
// 	fmt.Println(string(decryptFile("sample.txt", "password1")))
// }
