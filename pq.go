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

package openssl

// Post-quantum primitives (OpenSSL 3.5+): ML-DSA (FIPS 204) signatures, ML-KEM (FIPS 203) encapsulation, and HKDF
// extract/expand. Algorithms are fetched with the default properties, so when FIPS mode is enabled (FIPSModeSet) they
// come from the FIPS provider. Errors never include key material.
//
// OpenSSL's error queue is per thread, so every function that reads or clears it after a failing call locks the
// goroutine to its OS thread first.

/*
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

// OPENSSL_free and OPENSSL_clear_free are macros, which cgo cannot call.
static void goopenssl_pq_free(void *p) { OPENSSL_free(p); }
static void goopenssl_pq_clear_free(void *p, size_t len) { OPENSSL_clear_free(p, len); }

static EVP_PKEY *goopenssl_pq_generate(const char *alg) {
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	if (ctx == NULL)
		return NULL;
	if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pkey) != 1)
		pkey = NULL;
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

// goopenssl_pq_from_octets builds a key from one octet-string parameter: the seed (keypair) or the encoded public key.
static EVP_PKEY *goopenssl_pq_from_octets(const char *alg, const char *param, const unsigned char *buf, size_t len,
	int selection) {
	EVP_PKEY *pkey = NULL;
	OSSL_PARAM params[2];
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	if (ctx == NULL)
		return NULL;
	params[0] = OSSL_PARAM_construct_octet_string(param, (void *)buf, len);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_PKEY_fromdata_init(ctx) != 1 || EVP_PKEY_fromdata(ctx, &pkey, selection, params) != 1)
		pkey = NULL;
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

// goopenssl_pq_get_octets copies an octet-string key parameter into a new buffer; the caller must
// OPENSSL_clear_free it.
static unsigned char *goopenssl_pq_get_octets(EVP_PKEY *pkey, const char *param, size_t *len) {
	unsigned char *buf;
	if (EVP_PKEY_get_octet_string_param(pkey, param, NULL, 0, len) != 1 || *len == 0)
		return NULL;
	buf = OPENSSL_malloc(*len);
	if (buf == NULL)
		return NULL;
	if (EVP_PKEY_get_octet_string_param(pkey, param, buf, *len, len) != 1) {
		OPENSSL_clear_free(buf, *len);
		return NULL;
	}
	return buf;
}

// goopenssl_mldsa_sign signs msg with pure ML-DSA and an empty context. The caller must OPENSSL_free *sig.
static int goopenssl_mldsa_sign(EVP_PKEY *pkey, const char *alg, const unsigned char *msg, size_t msglen,
	unsigned char **sig, size_t *siglen) {
	int ok = 0;
	EVP_SIGNATURE *s = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	*sig = NULL;
	if (ctx == NULL)
		goto end;
	s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
	if (s == NULL || EVP_PKEY_sign_message_init(ctx, s, NULL) != 1)
		goto end;
	if (EVP_PKEY_sign(ctx, NULL, siglen, msg, msglen) != 1)
		goto end;
	*sig = OPENSSL_malloc(*siglen);
	if (*sig == NULL)
		goto end;
	if (EVP_PKEY_sign(ctx, *sig, siglen, msg, msglen) != 1) {
		OPENSSL_free(*sig);
		*sig = NULL;
		goto end;
	}
	ok = 1;
end:
	EVP_SIGNATURE_free(s);
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

static int goopenssl_mldsa_verify(EVP_PKEY *pkey, const char *alg, const unsigned char *msg, size_t msglen,
	const unsigned char *sig, size_t siglen) {
	int ok = 0;
	EVP_SIGNATURE *s = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (ctx == NULL)
		goto end;
	s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
	if (s == NULL || EVP_PKEY_verify_message_init(ctx, s, NULL) != 1)
		goto end;
	ok = EVP_PKEY_verify(ctx, sig, siglen, msg, msglen) == 1;
end:
	EVP_SIGNATURE_free(s);
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

// goopenssl_mlkem_encapsulate returns the ciphertext and shared secret. The caller must OPENSSL_free *enc and
// OPENSSL_clear_free *ss.
static int goopenssl_mlkem_encapsulate(EVP_PKEY *pkey, unsigned char **enc, size_t *enclen, unsigned char **ss,
	size_t *sslen) {
	int ok = 0;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	*enc = NULL;
	*ss = NULL;
	if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) != 1)
		goto end;
	if (EVP_PKEY_encapsulate(ctx, NULL, enclen, NULL, sslen) != 1)
		goto end;
	*enc = OPENSSL_malloc(*enclen);
	*ss = OPENSSL_malloc(*sslen);
	if (*enc == NULL || *ss == NULL)
		goto end;
	ok = EVP_PKEY_encapsulate(ctx, *enc, enclen, *ss, sslen) == 1;
end:
	if (!ok) {
		OPENSSL_free(*enc);
		OPENSSL_clear_free(*ss, *sslen);
		*enc = NULL;
		*ss = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

// goopenssl_mlkem_decapsulate returns the shared secret; the caller must OPENSSL_clear_free *ss.
static int goopenssl_mlkem_decapsulate(EVP_PKEY *pkey, const unsigned char *enc, size_t enclen, unsigned char **ss,
	size_t *sslen) {
	int ok = 0;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	*ss = NULL;
	if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) != 1)
		goto end;
	if (EVP_PKEY_decapsulate(ctx, NULL, sslen, enc, enclen) != 1)
		goto end;
	*ss = OPENSSL_malloc(*sslen);
	if (*ss == NULL)
		goto end;
	ok = EVP_PKEY_decapsulate(ctx, *ss, sslen, enc, enclen) == 1;
end:
	if (!ok) {
		OPENSSL_clear_free(*ss, *sslen);
		*ss = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

// goopenssl_hkdf runs HKDF in mode "EXTRACT_ONLY" (key = IKM) or "EXPAND_ONLY" (key = PRK).
static int goopenssl_hkdf(const char *md, const char *mode, const unsigned char *key, size_t keylen,
	const unsigned char *salt, size_t saltlen, const unsigned char *info, size_t infolen, unsigned char *out,
	size_t outlen) {
	int ok = 0;
	OSSL_PARAM params[6], *p = params;
	EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	EVP_KDF_CTX *ctx = NULL;
	if (kdf == NULL)
		return 0;
	ctx = EVP_KDF_CTX_new(kdf);
	if (ctx == NULL)
		goto end;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)md, 0);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char *)mode, 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, keylen);
	if (salt != NULL)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen);
	if (info != NULL)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, infolen);
	*p = OSSL_PARAM_construct_end();
	ok = EVP_KDF_derive(ctx, out, outlen, params) == 1;
end:
	EVP_KDF_CTX_free(ctx);
	EVP_KDF_free(kdf);
	return ok;
}

static int goopenssl_md_size(const char *md) {
	int size = 0;
	EVP_MD *m = EVP_MD_fetch(NULL, md, NULL);
	if (m != NULL) {
		size = EVP_MD_get_size(m);
		EVP_MD_free(m);
	}
	return size;
}

static const char *goopenssl_pkey_provider(const EVP_PKEY *pkey) {
	const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(pkey);
	return prov == NULL ? NULL : OSSL_PROVIDER_get0_name(prov);
}

static const char *goopenssl_signature_provider(const char *alg) {
	const char *name = NULL;
	EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(NULL, alg, NULL);
	if (s != NULL) {
		name = OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(s));
		EVP_SIGNATURE_free(s);
	}
	return name;
}

static const char *goopenssl_kem_provider(const char *alg) {
	const char *name = NULL;
	EVP_KEM *k = EVP_KEM_fetch(NULL, alg, NULL);
	if (k != NULL) {
		name = OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(k));
		EVP_KEM_free(k);
	}
	return name;
}

static const char *goopenssl_kdf_provider(const char *alg) {
	const char *name = NULL;
	EVP_KDF *k = EVP_KDF_fetch(NULL, alg, NULL);
	if (k != NULL) {
		name = OSSL_PROVIDER_get0_name(EVP_KDF_get0_provider(k));
		EVP_KDF_free(k);
	}
	return name;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// ML-DSA parameter sets and ML-KEM variants, by their OpenSSL algorithm names.
const (
	MLDSA44   = "ML-DSA-44"
	MLDSA65   = "ML-DSA-65"
	MLDSA87   = "ML-DSA-87"
	MLKEM768  = "ML-KEM-768"
	MLKEM1024 = "ML-KEM-1024"
)

func checkMLDSAAlg(alg string) error {
	switch alg {
	case MLDSA44, MLDSA65, MLDSA87:
		return nil
	}
	return fmt.Errorf("unsupported ML-DSA parameter set %q", alg)
}

func checkMLKEMAlg(alg string) error {
	switch alg {
	case MLKEM768, MLKEM1024:
		return nil
	}
	return fmt.Errorf("unsupported ML-KEM variant %q", alg)
}

// ErrInvalidKey matches (errors.Is) the errors for key input OpenSSL rejects: wrong lengths and encodings it cannot
// import. Other failures, such as a provider in an error state, do not match it.
var ErrInvalidKey = errors.New("invalid key")

type invalidKeyError struct{ msg string }

func (e *invalidKeyError) Error() string        { return e.msg }
func (e *invalidKeyError) Is(target error) bool { return target == ErrInvalidKey }

func invalidKey(format string, args ...interface{}) error {
	return &invalidKeyError{msg: fmt.Sprintf(format, args...)}
}

// pqKey owns an EVP_PKEY for a post-quantum algorithm.
type pqKey struct {
	key *C.EVP_PKEY
	alg string
}

func newPQKey(key *C.EVP_PKEY, alg string) *pqKey {
	k := &pqKey{key: key, alg: alg}
	runtime.SetFinalizer(k, func(k *pqKey) { C.EVP_PKEY_free(k.key) })
	return k
}

// Algorithm returns the OpenSSL algorithm name, e.g. "ML-DSA-65".
func (k *pqKey) Algorithm() string { return k.alg }

func (k *pqKey) octets(param string) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cParam := C.CString(param)
	defer C.free(unsafe.Pointer(cParam))
	var n C.size_t
	buf := C.goopenssl_pq_get_octets(k.key, cParam, &n)
	runtime.KeepAlive(k)
	if buf == nil {
		C.ERR_clear_error()
		return nil, fmt.Errorf("failed to export %s %s parameter", k.alg, param)
	}
	defer C.goopenssl_pq_clear_free(unsafe.Pointer(buf), n)
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), nil
}

// PublicKeyBytes returns the encoded public key (FIPS 203/204 encoding).
func (k *pqKey) PublicKeyBytes() ([]byte, error) { return k.octets("pub") }

// Seed returns the private key seed: 32 bytes for ML-DSA (xi), 64 bytes for ML-KEM (d || z).
func (k *pqKey) Seed() ([]byte, error) { return k.octets("seed") }

// ProviderName returns the name of the provider that holds the key ("fips" for keys created in FIPS mode).
func (k *pqKey) ProviderName() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := C.goopenssl_pkey_provider(k.key)
	runtime.KeepAlive(k)
	return providerName(name)
}

func generatePQKey(alg string) (*pqKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Drop errors earlier calls left on this thread, so a failure reports only its own.
	C.ERR_clear_error()
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	key := C.goopenssl_pq_generate(cAlg)
	if key == nil {
		return nil, fmt.Errorf("failed generating %s key: %w", alg, errorFromErrorQueue())
	}
	return newPQKey(key, alg), nil
}

// publicKeySize is the FIPS 203/204 public key encoding length per algorithm.
var publicKeySize = map[string]int{
	MLDSA44: 1312, MLDSA65: 1952, MLDSA87: 2592,
	MLKEM768: 1184, MLKEM1024: 1568,
}

// checkPublicKey rejects public keys OpenSSL would not import, so that an import failure on a key that passes is a
// provider failure: a wrong length, or for ML-KEM a coefficient >= q (the FIPS 203 modulus check).
func checkPublicKey(alg string, pub []byte) error {
	if len(pub) != publicKeySize[alg] {
		return invalidKey("invalid %s public key length %d", alg, len(pub))
	}
	if alg == MLKEM768 || alg == MLKEM1024 {
		// ByteEncode12 of the vector t-hat, then the 32-byte seed rho.
		for i := 0; i+3 <= len(pub)-32; i += 3 {
			c0 := uint16(pub[i]) | uint16(pub[i+1]&0x0f)<<8
			c1 := uint16(pub[i+1])>>4 | uint16(pub[i+2])<<4
			if c0 >= 3329 || c1 >= 3329 {
				return invalidKey("invalid %s public key", alg)
			}
		}
	}
	return nil
}

// pqKeyFromOctets imports a seed or public key that the caller has already checked, so a failure here is reported as
// an OpenSSL failure (for example, a provider in an error state), not as ErrInvalidKey.
func pqKeyFromOctets(alg, param string, b []byte, selection C.int) (*pqKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(b) == 0 {
		return nil, invalidKey("empty %s %s", alg, param)
	}
	C.ERR_clear_error()
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	cParam := C.CString(param)
	defer C.free(unsafe.Pointer(cParam))
	key := C.goopenssl_pq_from_octets(cAlg, cParam, (*C.uchar)(unsafe.Pointer(&b[0])), C.size_t(len(b)), selection)
	if key == nil {
		// The queue holds library, function and reason strings only, never input bytes.
		return nil, fmt.Errorf("failed to import %s %s: %w", alg, param, errorFromErrorQueue())
	}
	return newPQKey(key, alg), nil
}

// MLDSAKey is an ML-DSA private key.
type MLDSAKey struct{ *pqKey }

// GenerateMLDSAKey generates an ML-DSA key for the parameter set alg (MLDSA44, MLDSA65 or MLDSA87).
func GenerateMLDSAKey(alg string) (*MLDSAKey, error) {
	if err := checkMLDSAAlg(alg); err != nil {
		return nil, err
	}
	k, err := generatePQKey(alg)
	if err != nil {
		return nil, err
	}
	return &MLDSAKey{k}, nil
}

// NewMLDSAPrivateKeyFromSeed derives the ML-DSA key for a 32-byte seed (FIPS 204 KeyGen_internal).
func NewMLDSAPrivateKeyFromSeed(alg string, seed []byte) (*MLDSAKey, error) {
	if err := checkMLDSAAlg(alg); err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, invalidKey("ML-DSA seed must be 32 bytes, got %d", len(seed))
	}
	k, err := pqKeyFromOctets(alg, "seed", seed, C.EVP_PKEY_KEYPAIR)
	if err != nil {
		return nil, err
	}
	return &MLDSAKey{k}, nil
}

// ExpandedKey returns the FIPS 204 skEncode private key encoding (rho || K || tr || s1 || s2 || t0). Tests check it
// against NIST ACVP keyGen vectors.
func (k *MLDSAKey) ExpandedKey() ([]byte, error) { return k.octets("priv") }

// SignMessage signs message with pure ML-DSA and an empty context string.
func (k *MLDSAKey) SignMessage(message []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Drop errors earlier calls left on this thread, so a failure reports only its own.
	C.ERR_clear_error()
	cAlg := C.CString(k.alg)
	defer C.free(unsafe.Pointer(cAlg))
	var msgPtr *C.uchar
	if len(message) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&message[0]))
	}
	var sig *C.uchar
	var sigLen C.size_t
	ok := C.goopenssl_mldsa_sign(k.key, cAlg, msgPtr, C.size_t(len(message)), &sig, &sigLen)
	runtime.KeepAlive(k)
	if ok != 1 {
		return nil, fmt.Errorf("%s signing failed: %w", k.alg, errorFromErrorQueue())
	}
	defer C.goopenssl_pq_free(unsafe.Pointer(sig))
	return C.GoBytes(unsafe.Pointer(sig), C.int(sigLen)), nil
}

// VerifyMLDSA verifies a pure ML-DSA signature (empty context) against an encoded public key.
func VerifyMLDSA(alg string, publicKey, message, signature []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := checkMLDSAAlg(alg); err != nil {
		return err
	}
	if err := checkPublicKey(alg, publicKey); err != nil {
		return err
	}
	pub, err := pqKeyFromOctets(alg, "pub", publicKey, C.EVP_PKEY_PUBLIC_KEY)
	if err != nil {
		return err
	}
	if len(signature) == 0 {
		return errors.New("ML-DSA signature verification failed")
	}
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	var msgPtr *C.uchar
	if len(message) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&message[0]))
	}
	ok := C.goopenssl_mldsa_verify(pub.key, cAlg, msgPtr, C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&signature[0])), C.size_t(len(signature)))
	runtime.KeepAlive(pub)
	if ok != 1 {
		C.ERR_clear_error()
		return errors.New("ML-DSA signature verification failed")
	}
	return nil
}

// MLKEMKey is an ML-KEM decapsulation (private) key.
type MLKEMKey struct{ *pqKey }

// GenerateMLKEMKey generates an ML-KEM key for alg (MLKEM768 or MLKEM1024).
func GenerateMLKEMKey(alg string) (*MLKEMKey, error) {
	if err := checkMLKEMAlg(alg); err != nil {
		return nil, err
	}
	k, err := generatePQKey(alg)
	if err != nil {
		return nil, err
	}
	return &MLKEMKey{k}, nil
}

// NewMLKEMPrivateKeyFromSeed derives the ML-KEM key for a 64-byte seed d || z (FIPS 203 ML-KEM.KeyGen_internal).
func NewMLKEMPrivateKeyFromSeed(alg string, seed []byte) (*MLKEMKey, error) {
	if err := checkMLKEMAlg(alg); err != nil {
		return nil, err
	}
	if len(seed) != 64 {
		return nil, invalidKey("ML-KEM seed must be 64 bytes, got %d", len(seed))
	}
	k, err := pqKeyFromOctets(alg, "seed", seed, C.EVP_PKEY_KEYPAIR)
	if err != nil {
		return nil, err
	}
	return &MLKEMKey{k}, nil
}

// EncapsulateMLKEM encapsulates to an encoded ML-KEM public key and returns the ciphertext and the 32-byte shared
// secret.
func EncapsulateMLKEM(alg string, publicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Drop errors earlier calls left on this thread, so a failure reports only its own.
	C.ERR_clear_error()
	if err := checkMLKEMAlg(alg); err != nil {
		return nil, nil, err
	}
	if err := checkPublicKey(alg, publicKey); err != nil {
		return nil, nil, err
	}
	pub, err := pqKeyFromOctets(alg, "pub", publicKey, C.EVP_PKEY_PUBLIC_KEY)
	if err != nil {
		return nil, nil, err
	}
	var enc, ss *C.uchar
	var encLen, ssLen C.size_t
	ok := C.goopenssl_mlkem_encapsulate(pub.key, &enc, &encLen, &ss, &ssLen)
	runtime.KeepAlive(pub)
	if ok != 1 {
		return nil, nil, fmt.Errorf("%s encapsulation failed: %w", alg, errorFromErrorQueue())
	}
	defer C.goopenssl_pq_free(unsafe.Pointer(enc))
	defer C.goopenssl_pq_clear_free(unsafe.Pointer(ss), ssLen)
	return C.GoBytes(unsafe.Pointer(enc), C.int(encLen)), C.GoBytes(unsafe.Pointer(ss), C.int(ssLen)), nil
}

// Decapsulate recovers the shared secret from an ML-KEM ciphertext. As FIPS 203 specifies, an invalid ciphertext of
// the right length yields a pseudorandom secret rather than an error.
func (k *MLKEMKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("%s decapsulation failed", k.alg)
	}
	var ss *C.uchar
	var ssLen C.size_t
	ok := C.goopenssl_mlkem_decapsulate(k.key, (*C.uchar)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		&ss, &ssLen)
	runtime.KeepAlive(k)
	if ok != 1 {
		C.ERR_clear_error()
		return nil, fmt.Errorf("%s decapsulation failed", k.alg)
	}
	defer C.goopenssl_pq_clear_free(unsafe.Pointer(ss), ssLen)
	return C.GoBytes(unsafe.Pointer(ss), C.int(ssLen)), nil
}

func hkdf(md, mode string, key, salt, info []byte, length int) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if length <= 0 {
		return nil, errors.New("HKDF output length must be positive")
	}
	cMd := C.CString(md)
	defer C.free(unsafe.Pointer(cMd))
	cMode := C.CString(mode)
	defer C.free(unsafe.Pointer(cMode))

	// OpenSSL needs non-NULL pointers for present parameters, including empty ones.
	var zero [1]byte
	ptr := func(b []byte) *C.uchar {
		if len(b) == 0 {
			return (*C.uchar)(unsafe.Pointer(&zero[0]))
		}
		return (*C.uchar)(unsafe.Pointer(&b[0]))
	}
	var saltPtr, infoPtr *C.uchar
	if salt != nil {
		saltPtr = ptr(salt)
	}
	if info != nil {
		infoPtr = ptr(info)
	}

	out := make([]byte, length)
	ok := C.goopenssl_hkdf(cMd, cMode, ptr(key), C.size_t(len(key)), saltPtr, C.size_t(len(salt)), infoPtr,
		C.size_t(len(info)), (*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(length))
	if ok != 1 {
		C.ERR_clear_error()
		return nil, fmt.Errorf("HKDF %s with %s failed", mode, md)
	}
	return out, nil
}

// HKDFExtract computes HKDF-Extract(salt, ikm) (RFC 5869) with digest md, e.g. "SHA256". The output has the digest's
// length. A nil or empty salt is the zero-length salt.
func HKDFExtract(md string, salt, ikm []byte) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cMd := C.CString(md)
	defer C.free(unsafe.Pointer(cMd))
	size := int(C.goopenssl_md_size(cMd))
	if size <= 0 {
		C.ERR_clear_error()
		return nil, fmt.Errorf("unsupported HKDF digest %q", md)
	}
	if salt == nil {
		salt = []byte{}
	}
	return hkdf(md, "EXTRACT_ONLY", ikm, salt, nil, size)
}

// HKDFExpand computes HKDF-Expand(prk, info, length) (RFC 5869) with digest md.
func HKDFExpand(md string, prk, info []byte, length int) ([]byte, error) {
	if info == nil {
		info = []byte{}
	}
	return hkdf(md, "EXPAND_ONLY", prk, nil, info, length)
}

func providerName(name *C.char) (string, error) {
	if name == nil {
		C.ERR_clear_error()
		return "", errors.New("algorithm not available")
	}
	return C.GoString(name), nil
}

// SignatureProviderName returns the name of the provider that serves signature algorithm alg under the current
// default properties ("fips" in FIPS mode).
func SignatureProviderName(alg string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	return providerName(C.goopenssl_signature_provider(cAlg))
}

// KEMProviderName returns the name of the provider that serves KEM alg under the current default properties.
func KEMProviderName(alg string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	return providerName(C.goopenssl_kem_provider(cAlg))
}

// KDFProviderName returns the name of the provider that serves KDF alg under the current default properties.
func KDFProviderName(alg string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))
	return providerName(C.goopenssl_kdf_provider(cAlg))
}
