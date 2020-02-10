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
//     RSA *rsa= RSA_new();
//     if(rsa == NULL)
//     {
//         printf( "Failed to create RSA");
//     }
//
//     BIGNUM* d = BN_new();
//     BN_hex2bn(&d, d_hex);
//
//     BIGNUM* n = BN_new();
//	   BN_hex2bn(&n, n_hex);
//	
// 	   BIGNUM* e = BN_new();
//     BN_hex2bn(&e, e_hex);
//
//     rsa->d = d;
// 	   rsa->n = n;
//	   rsa->e = e;
//
//     rsa->flags |= RSA_FLAG_NO_BLINDING;    
//
//     return rsa;
// }
//
// int PrivateDecrypt(char* d_hex, char* n_hex, char* e_hex, unsigned char* enc_data, int data_len, unsigned char *decrypted)
// {
//     RSA* rsa = CreatePrivateRSA(d_hex, n_hex, e_hex);
//     int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
//     RSA_free(rsa);
//     return result;
// }
// void printLastError()
// {
//     char * err = malloc(130);;
//     ERR_load_crypto_strings();
//     ERR_error_string(ERR_get_error(), err);
//     printf("\nPrivate Encrypt failed ERROR: %s\n", err);
//     free(err);
// }
// void getLastError(char* err)
// {
//     ERR_load_crypto_strings();
//     ERR_error_string(ERR_get_error(), err);
// }
import "C"

import (
	"unsafe"
	"math/big"	
	"fmt"
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
	decLen := C.PrivateDecrypt(cHexD, cHexN, cHexE,(*C.byte)(unsafe.Pointer(&msgBytes[0])), C.int(len(msgBytes)), (*C.byte)(unsafe.Pointer(&decrypted[0])))
	if decLen == -1 || decLen > 512 {
		ptr := C.malloc(C.sizeof_char * 130)
    	defer C.free(unsafe.Pointer(ptr))
		C.getLastError((*C.char)(ptr))
		return nil, fmt.Errorf("Private decrypt of OpenSSL failed: %s", C.GoString((*C.char)(ptr)))
	}
	return decrypted[:decLen], nil
}
