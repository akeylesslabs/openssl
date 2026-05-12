package openssl

// #include "shim.h"
// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <stdio.h>
// #include <stdlib.h>
// typedef unsigned char byte;
// int padding = RSA_NO_PADDING; //3
// RSA * CreatePrivateRSA(char* d_hex, char* n_hex, char* e_hex)
// {
//     RSA *rsa = RSA_new();
//     if(rsa == NULL)
//     {
//         printf( "Failed to create RSA");
//         return NULL;
//     }
//
//     BIGNUM *d = NULL;
//     BIGNUM *n = NULL;
//     BIGNUM *e = NULL;
//
//     if (BN_hex2bn(&d, d_hex) == 0 ||
//         BN_hex2bn(&n, n_hex) == 0 ||
//         BN_hex2bn(&e, e_hex) == 0 ||
//         RSA_set0_key(rsa, n, e, d) != 1)
//     {
//         BN_free(d);
//         BN_free(n);
//         BN_free(e);
//         RSA_free(rsa);
//         return NULL;
//     }
//
//     RSA_set_flags(rsa, RSA_FLAG_NO_BLINDING);
//
//     return rsa;
// }
//
// int PrivateDecrypt(char* d_hex, char* n_hex, char* e_hex, unsigned char* enc_data, int data_len, unsigned char *decrypted)
// {
//     RSA* rsa = CreatePrivateRSA(d_hex, n_hex, e_hex);
//     if (rsa == NULL) {
//         return -1;
//     }
//     int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
//     RSA_free(rsa);
//     return result;
// }
//
// void getLastError(char* err)
// {
//     ERR_error_string_n(ERR_get_error(), err, 130);
// }
import "C"

import (
	"fmt"
	"math/big"
	"unsafe"
)

func RsaPrivateDecrypt(D *big.Int, N *big.Int, E *big.Int, msg []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(msg)
	msgBytes := m.Bytes()

	cHexD := C.CString(fmt.Sprintf("%X", D))
	defer C.free(unsafe.Pointer(cHexD))

	cHexN := C.CString(fmt.Sprintf("%X", N))
	defer C.free(unsafe.Pointer(cHexN))

	cHexE := C.CString(fmt.Sprintf("%X", E))
	defer C.free(unsafe.Pointer(cHexE))

	decrypted := make([]byte, 512) // 512 is the maximum decrypted message length for RSA 4096.
	decLen := C.PrivateDecrypt(cHexD, cHexN, cHexE, (*C.byte)(unsafe.Pointer(&msgBytes[0])), C.int(len(msgBytes)), (*C.byte)(unsafe.Pointer(&decrypted[0])))
	if decLen == -1 || decLen > 512 {
		ptr := C.malloc(C.sizeof_char * 130)
		defer C.free(unsafe.Pointer(ptr))
		C.getLastError((*C.char)(ptr))
		return nil, fmt.Errorf("Private decrypt of OpenSSL failed: %s", C.GoString((*C.char)(ptr)))
	}
	return decrypted[:decLen], nil
}
