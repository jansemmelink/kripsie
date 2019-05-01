package encryption_test

import (
	"fmt"
	"testing"

	"github.com/jansemmelink/kripsie/lib/encryption"
)

func TestOne(t *testing.T) {
	fmt.Println("Starting the application...")
	text := "1" //"HelloWorld"
	key := "2"  //"1234"
	ciphertext := encryption.Encrypt([]byte(text), key)
	fmt.Printf("Encrypted: %x\n", ciphertext)
	plaindata, err := encryption.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	plaintext := string(plaindata)
	fmt.Printf("Decrypted: %s\n", plaintext)
	if plaintext != text {
		t.Fatalf("Encrypted \"%s\" but decrypted different text \"%s\"", text, plaintext)
	}

}
