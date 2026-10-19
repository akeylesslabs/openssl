// Copyright (C) 2026. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build go1.27
// +build go1.27

package openssl

// These tests check the OpenSSL primitives against Go's standard library implementations (crypto/mldsa,
// crypto/mlkem, crypto/hkdf), which are independent, NIST CAVP-tested implementations of the same standards, plus
// the RFC 5869 HKDF vectors. Set GOOPENSSL_TEST_FIPS=1 (with OPENSSL_CONF pointing at a FIPS-enabled configuration)
// to run them with the FIPS provider and assert that it serves every algorithm.

import (
	"bytes"
	gohkdf "crypto/hkdf"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func pqTestSetup(t *testing.T) {
	t.Helper()
	if os.Getenv("GOOPENSSL_TEST_FIPS") != "1" {
		return
	}
	if err := FIPSModeSet(true); err != nil {
		t.Fatalf("enabling FIPS mode: %v", err)
	}
	if !FIPSMode() {
		t.Fatal("FIPS mode not enabled")
	}
	for alg, get := range map[string]func(string) (string, error){
		MLDSA44: SignatureProviderName, MLDSA65: SignatureProviderName, MLDSA87: SignatureProviderName,
		MLKEM768: KEMProviderName, MLKEM1024: KEMProviderName, "HKDF": KDFProviderName,
	} {
		name, err := get(alg)
		if err != nil || name != "fips" {
			t.Fatalf("%s served by provider %q (err %v), want fips", alg, name, err)
		}
	}
}

// requireKeyProvider checks, in FIPS mode, that the FIPS provider holds key k.
func requireKeyProvider(t *testing.T, k interface{ ProviderName() (string, error) }) {
	t.Helper()
	if os.Getenv("GOOPENSSL_TEST_FIPS") != "1" {
		return
	}
	name, err := k.ProviderName()
	if err != nil || name != "fips" {
		t.Fatalf("key held by provider %q (err %v), want fips", name, err)
	}
	t.Log("FIPS provider holds the key")
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var mldsaParams = []struct {
	alg          string
	params       mldsa.Parameters
	expandedSize int
}{
	{MLDSA44, mldsa.MLDSA44(), 2560},
	{MLDSA65, mldsa.MLDSA65(), 4032},
	{MLDSA87, mldsa.MLDSA87(), 4896},
}

func TestMLDSAMatchesGo(t *testing.T) {
	pqTestSetup(t)
	msg := []byte("post-quantum message")

	for _, tc := range mldsaParams {
		t.Run(tc.alg, func(t *testing.T) {
			// Same seed, same key: OpenSSL KeyGen_internal matches Go's.
			seed := randomBytes(t, 32)
			k, err := NewMLDSAPrivateKeyFromSeed(tc.alg, seed)
			if err != nil {
				t.Fatal(err)
			}
			requireKeyProvider(t, k)
			goKey, err := mldsa.NewPrivateKey(tc.params, seed)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := k.PublicKeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub, goKey.PublicKey().Bytes()) {
				t.Fatal("public key differs from crypto/mldsa for the same seed")
			}
			gotSeed, err := k.Seed()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSeed, seed) {
				t.Fatal("exported seed differs from the input seed")
			}

			// skEncode starts with rho (the first 32 bytes of the public key), K, and tr = SHAKE256(pk, 64).
			expanded, err := k.ExpandedKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(expanded) != tc.expandedSize || !bytes.Equal(expanded[:32], pub[:32]) ||
				!bytes.Equal(expanded[64:128], sha3.SumSHAKE256(pub, 64)) {
				t.Fatal("expanded key does not match the public key")
			}

			// OpenSSL signs, Go verifies; Go signs, OpenSSL verifies.
			sig, err := k.SignMessage(msg)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != tc.params.SignatureSize() {
				t.Fatalf("signature size %d, want %d", len(sig), tc.params.SignatureSize())
			}
			if err := mldsa.Verify(goKey.PublicKey(), msg, sig, nil); err != nil {
				t.Fatalf("crypto/mldsa rejects the OpenSSL signature: %v", err)
			}
			goSig, err := goKey.Sign(nil, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyMLDSA(tc.alg, pub, msg, goSig); err != nil {
				t.Fatalf("OpenSSL rejects the crypto/mldsa signature: %v", err)
			}

			// Negative cases.
			if VerifyMLDSA(tc.alg, pub, []byte("other message"), sig) == nil {
				t.Fatal("verified a signature over a different message")
			}
			bad := append([]byte{}, sig...)
			bad[len(bad)/2] ^= 1
			if VerifyMLDSA(tc.alg, pub, msg, bad) == nil {
				t.Fatal("verified a tampered signature")
			}
			other, err := GenerateMLDSAKey(tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			otherPub, err := other.PublicKeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			if VerifyMLDSA(tc.alg, otherPub, msg, sig) == nil {
				t.Fatal("verified with another key")
			}
			if VerifyMLDSA(tc.alg, pub, msg, nil) == nil {
				t.Fatal("verified an empty signature")
			}

			// Empty message is a valid input.
			emptySig, err := k.SignMessage(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := mldsa.Verify(goKey.PublicKey(), nil, emptySig, nil); err != nil {
				t.Fatalf("empty-message signature: %v", err)
			}
			if err := VerifyMLDSA(tc.alg, pub, []byte{}, emptySig); err != nil {
				t.Fatalf("OpenSSL rejects the empty-message signature: %v", err)
			}
			goEmptySig, err := goKey.Sign(nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyMLDSA(tc.alg, pub, nil, goEmptySig); err != nil {
				t.Fatalf("OpenSSL rejects the crypto/mldsa empty-message signature: %v", err)
			}
		})
	}
}

func TestMLDSAGenerateAndInputChecks(t *testing.T) {
	pqTestSetup(t)
	for _, tc := range mldsaParams {
		k, err := GenerateMLDSAKey(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		if k.Algorithm() != tc.alg {
			t.Fatalf("algorithm %q, want %q", k.Algorithm(), tc.alg)
		}
		seed, err := k.Seed()
		if err != nil {
			t.Fatal(err)
		}
		goKey, err := mldsa.NewPrivateKey(tc.params, seed)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.PublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, goKey.PublicKey().Bytes()) {
			t.Fatal("generated key's public key does not match its seed")
		}
	}

	if _, err := GenerateMLDSAKey("ML-DSA-99"); err == nil {
		t.Fatal("accepted an unknown parameter set")
	}
	if _, err := NewMLDSAPrivateKeyFromSeed(MLDSA65, make([]byte, 31)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("31-byte seed: %v, want ErrInvalidKey", err)
	}
	if err := VerifyMLDSA(MLDSA65, []byte("short"), []byte("m"), []byte("s")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("malformed public key: %v, want ErrInvalidKey", err)
	}
}

var mlkemVariants = []struct {
	alg    string
	encLen int
	newGo  func(seed []byte) (encapsulationKey []byte, decapsulate func([]byte) ([]byte, error), err error)
	encap  func(pub []byte) (ss, ct []byte, err error)
}{
	{
		alg: MLKEM768, encLen: mlkem.CiphertextSize768,
		newGo: func(seed []byte) ([]byte, func([]byte) ([]byte, error), error) {
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, err
			}
			return dk.EncapsulationKey().Bytes(), dk.Decapsulate, nil
		},
		encap: func(pub []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey768(pub)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ss, ct, nil
		},
	},
	{
		alg: MLKEM1024, encLen: mlkem.CiphertextSize1024,
		newGo: func(seed []byte) ([]byte, func([]byte) ([]byte, error), error) {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, nil, err
			}
			return dk.EncapsulationKey().Bytes(), dk.Decapsulate, nil
		},
		encap: func(pub []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey1024(pub)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ss, ct, nil
		},
	},
}

func TestMLKEMMatchesGo(t *testing.T) {
	pqTestSetup(t)
	for _, tc := range mlkemVariants {
		t.Run(tc.alg, func(t *testing.T) {
			seed := randomBytes(t, 64)
			k, err := NewMLKEMPrivateKeyFromSeed(tc.alg, seed)
			if err != nil {
				t.Fatal(err)
			}
			requireKeyProvider(t, k)
			goPub, goDecap, err := tc.newGo(seed)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := k.PublicKeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub, goPub) {
				t.Fatal("encapsulation key differs from crypto/mlkem for the same seed")
			}
			gotSeed, err := k.Seed()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSeed, seed) {
				t.Fatal("exported seed differs from the input seed")
			}

			// OpenSSL encapsulates, Go decapsulates.
			ct, ss, err := EncapsulateMLKEM(tc.alg, pub)
			if err != nil {
				t.Fatal(err)
			}
			if len(ct) != tc.encLen || len(ss) != 32 {
				t.Fatalf("ciphertext %d bytes, secret %d bytes", len(ct), len(ss))
			}
			goSS, err := goDecap(ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, goSS) {
				t.Fatal("crypto/mlkem decapsulates a different secret")
			}

			// Go encapsulates, OpenSSL decapsulates.
			goSS2, goCT, err := tc.encap(pub)
			if err != nil {
				t.Fatal(err)
			}
			ss2, err := k.Decapsulate(goCT)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss2, goSS2) {
				t.Fatal("OpenSSL decapsulates a different secret from the crypto/mlkem ciphertext")
			}

			// Implicit rejection: a modified ciphertext gives the same pseudorandom secret in both implementations,
			// different from the real one.
			bad := append([]byte{}, ct...)
			bad[0] ^= 1
			rejSS, err := k.Decapsulate(bad)
			if err != nil {
				t.Fatal(err)
			}
			goRejSS, err := goDecap(bad)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(rejSS, ss) || !bytes.Equal(rejSS, goRejSS) {
				t.Fatal("implicit rejection differs from crypto/mlkem")
			}

			if _, err := k.Decapsulate(ct[:len(ct)-1]); err == nil {
				t.Fatal("accepted a short ciphertext")
			}
		})
	}

	if _, err := NewMLKEMPrivateKeyFromSeed(MLKEM768, make([]byte, 32)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("32-byte seed: %v, want ErrInvalidKey", err)
	}
	if _, _, err := EncapsulateMLKEM(MLKEM768, []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("malformed public key: %v, want ErrInvalidKey", err)
	}
	// A coefficient >= q fails the FIPS 203 modulus check, in Go before OpenSSL.
	for _, tc := range mlkemVariants {
		k, err := GenerateMLKEMKey(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.PublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		for _, coeff := range []int{0, 1} {
			bad := append([]byte{}, pub...)
			if coeff == 0 {
				bad[0], bad[1] = 0x01, bad[1]&0xf0|0x0d // c0 = 0xd01 = 3329
			} else {
				bad[1], bad[2] = bad[1]&0x0f|0x10, 0xd0 // c1 = 0xd01 = 3329
			}
			if _, _, err := EncapsulateMLKEM(tc.alg, bad); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("%s non-canonical coefficient %d: %v, want ErrInvalidKey", tc.alg, coeff, err)
			}
		}
		if _, _, err := tc.encap(pub); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := GenerateMLKEMKey("ML-KEM-512"); errors.Is(err, ErrInvalidKey) {
		t.Fatal("an unsupported variant is not an invalid key")
	}
	if _, err := GenerateMLKEMKey("ML-KEM-512"); err == nil {
		t.Fatal("accepted ML-KEM-512, which is not offered")
	}
}

func TestMLKEMGenerate(t *testing.T) {
	pqTestSetup(t)
	for _, tc := range mlkemVariants {
		k, err := GenerateMLKEMKey(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := k.Seed()
		if err != nil {
			t.Fatal(err)
		}
		goPub, _, err := tc.newGo(seed)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.PublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pub, goPub) {
			t.Fatal("generated key's public key does not match its seed")
		}
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 5869 Appendix A test cases 1 and 3 (SHA-256).
func TestHKDFRFC5869(t *testing.T) {
	pqTestSetup(t)
	cases := []struct {
		ikm, salt, info, prk, okm string
		l                         int
	}{
		{
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
			l:    42,
		},
		{
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "",
			info: "",
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
			l:    42,
		},
	}
	for i, c := range cases {
		prk, err := HKDFExtract("SHA256", unhex(t, c.salt), unhex(t, c.ikm))
		if err != nil {
			t.Fatalf("case %d extract: %v", i, err)
		}
		if hex.EncodeToString(prk) != c.prk {
			t.Fatalf("case %d PRK %x, want %s", i, prk, c.prk)
		}
		okm, err := HKDFExpand("SHA256", prk, unhex(t, c.info), c.l)
		if err != nil {
			t.Fatalf("case %d expand: %v", i, err)
		}
		if hex.EncodeToString(okm) != c.okm {
			t.Fatalf("case %d OKM %x, want %s", i, okm, c.okm)
		}
	}
}

// SHA-384 (the HPKE KDF for ML-KEM-1024) against crypto/hkdf, including the empty salt and info HPKE uses.
func TestHKDFSHA384MatchesGo(t *testing.T) {
	pqTestSetup(t)
	for _, salt := range [][]byte{nil, randomBytes(t, 48)} {
		ikm := randomBytes(t, 64)
		info := []byte("HPKE-v1 test info")
		prk, err := HKDFExtract("SHA384", salt, ikm)
		if err != nil {
			t.Fatal(err)
		}
		goPRK, err := gohkdf.Extract(sha512.New384, ikm, salt)
		if err != nil {
			t.Fatal(err)
		}
		if len(prk) != sha512.Size384 || !bytes.Equal(prk, goPRK) {
			t.Fatal("HKDF-Extract differs from crypto/hkdf")
		}
		for _, inf := range [][]byte{nil, info} {
			okm, err := HKDFExpand("SHA384", prk, inf, 77)
			if err != nil {
				t.Fatal(err)
			}
			goOKM, err := gohkdf.Expand(sha512.New384, prk, string(inf), 77)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(okm, goOKM) {
				t.Fatal("HKDF-Expand differs from crypto/hkdf")
			}
		}
	}
	if _, err := HKDFExpand("SHA256", randomBytes(t, 32), nil, 0); err == nil {
		t.Fatal("accepted a zero output length")
	}
	if _, err := HKDFExpand("SHA256", randomBytes(t, 32), nil, 255*sha256.Size+1); err == nil {
		t.Fatal("accepted an output longer than 255 hash lengths")
	}
	if _, err := HKDFExtract("NO-SUCH-DIGEST", nil, []byte("ikm")); err == nil {
		t.Fatal("accepted an unknown digest")
	}
}

// Errors never echo key material.
func TestPQErrorsDoNotEchoInput(t *testing.T) {
	pqTestSetup(t)
	secret := bytes.Repeat([]byte{0xA5}, 64)
	var errs []error
	_, err := NewMLKEMPrivateKeyFromSeed(MLKEM768, secret[:63])
	errs = append(errs, err)
	errs = append(errs, VerifyMLDSA(MLDSA65, secret, []byte("m"), secret))
	_, _, err = EncapsulateMLKEM(MLKEM1024, secret)
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "a5a5") || strings.Contains(msg, string(secret[:4])) {
			t.Fatalf("error echoes input: %v", err)
		}
	}
}

// NIST ACVP ML-DSA keyGen vectors (FIPS 204 KeyGen_internal), one per parameter set, check seed loading, the public key
// and the expanded private key byte for byte.
func TestMLDSAKeyGenACVP(t *testing.T) {
	pqTestSetup(t)
	raw, err := os.ReadFile("testdata/mldsa_keygen_acvp.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors map[string]struct{ Seed, Pk, Sk string }
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, tc := range mldsaParams {
		v, ok := file.Vectors[tc.alg]
		if !ok {
			t.Fatalf("no vector for %s", tc.alg)
		}
		k, err := NewMLDSAPrivateKeyFromSeed(tc.alg, unhex(t, v.Seed))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.PublicKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(hex.EncodeToString(pub), v.Pk) {
			t.Fatalf("%s public key differs from the ACVP vector", tc.alg)
		}
		expanded, err := k.ExpandedKey()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(hex.EncodeToString(expanded), v.Sk) {
			t.Fatalf("%s expanded key differs from the ACVP vector", tc.alg)
		}
	}
}

// Keys are shared between goroutines by the callers' engines.
func TestPQConcurrentUse(t *testing.T) {
	pqTestSetup(t)
	dsa, err := GenerateMLDSAKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	dsaPub, err := dsa.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	kem, err := GenerateMLKEMKey(MLKEM768)
	if err != nil {
		t.Fatal(err)
	}
	kemPub, err := kem.PublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				msg := []byte{byte(g), byte(i)}
				sig, err := dsa.SignMessage(msg)
				if err == nil {
					err = VerifyMLDSA(MLDSA65, dsaPub, msg, sig)
				}
				if err == nil && VerifyMLDSA(MLDSA65, []byte("bad"), msg, sig) == nil {
					err = errors.New("verified with a malformed public key")
				}
				var ct, ss, ss2 []byte
				if err == nil {
					ct, ss, err = EncapsulateMLKEM(MLKEM768, kemPub)
				}
				if err == nil {
					ss2, err = kem.Decapsulate(ct)
				}
				if err == nil && !bytes.Equal(ss, ss2) {
					err = errors.New("shared secrets differ")
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
