package openssl

import (	
	"testing"
	"bytes"
)

func TestGenerateRandomBytes(t *testing.T) {
	emptyByteVar := make([]byte, 34)
	res, err := GenerateRandomBytes(34)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 34 {
		t.Fatal("Must generate bytes")
	}

	if bytes.Equal(res, emptyByteVar) {
		t.Fatal("Must not be empty")
	}	
}