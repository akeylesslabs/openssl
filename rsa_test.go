package openssl

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	math_rand "math/rand"
	"testing"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[math_rand.Intn(len(letters))]
	}
	return string(b)
}

func encrypt(c *big.Int, e int, m *big.Int, N *big.Int) *big.Int {
	E := big.NewInt(int64(e))
	c.Exp(m, E, N)
	return c
}

func TestRsaPrivateDecrypt(t *testing.T) {
	key, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	msgBytes := []byte("Test Split RSA Key")
	decrypted, err := RsaPrivateDecrypt(key.D, key.N, big.NewInt(int64(key.E)), msgBytes)
	if err != nil {
		t.Fatal(err)
	}

	check := encrypt(new(big.Int), key.PublicKey.E, new(big.Int).SetBytes(decrypted), key.PublicKey.N)

	m := new(big.Int).SetBytes(msgBytes)
	if m.Cmp(check) != 0 {
		t.Fatal(errors.New("The decryption output does not match the original message"))
	}
}

func TestRsaPrivateDecryptVarLength(t *testing.T) {
	mapRsa := map[int]int {1024:117, 2048:245, 4096:500} // RSA bits mapped to max message length
	for bits, mLen := range mapRsa {
		key, err := rsa.GenerateKey(crypto_rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}

		math_rand.Seed(time.Now().UnixNano())
		msgBytes := []byte(randSeq(mLen))

		decrypted, err := RsaPrivateDecrypt(key.D, key.N, big.NewInt(int64(key.E)), msgBytes)
		if err != nil {
			t.Fatal(err)
		}

		check := encrypt(new(big.Int), key.PublicKey.E, new(big.Int).SetBytes(decrypted), key.PublicKey.N)
		m := new(big.Int).SetBytes(msgBytes)
		if m.Cmp(check) != 0 {
			t.Fatal(errors.New("The decryption output does not match the original message"))
		}
	}	
}

func TestRsaPrivateDecryptBigLength(t *testing.T) {
	mapRsa := map[int]int {1024:256, 2048:512, 4096:1024} // RSA bits mapped to larger than supported message length
	for bits, mLen := range mapRsa {
		key, err := rsa.GenerateKey(crypto_rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}

		math_rand.Seed(time.Now().UnixNano())
		msgBytes := []byte(randSeq(mLen))

		_, err = RsaPrivateDecrypt(key.D, key.N, big.NewInt(int64(key.E)), msgBytes)
		if err == nil {
			t.Fatal(errors.New("Attempt to decrypt message larger than supported by RSA must fail"))
		}
	}	
}