package openssl

// #cgo CFLAGS: -I/usr/local/ssl/include/
// #cgo LDFLAGS: -L.  -lssl -lcrypto
/*
#include "shim.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/rand.h>
typedef unsigned char byte;
// Puts num cryptographically strong pseudo-random bytes into buf. 
// An error occurs if the PRNG has not been seeded with enough randomness to ensure an unpredictable byte sequence.
// Returns 1 on success, 0 otherwise
int GenerateRandomBytes(byte* buf, int n) {
    int rc = RAND_bytes(buf, n);
    if(rc != 1) {        
        fprintf(stderr, "GenerateRandomBytes failed.\n");
        ERR_print_errors_fp(stderr);
    }
    
    // int i;
    // for (i = 0; i < n; i++)
    // {
    //     if (i > 0) printf(":");
    //     printf("%02X", buf[i]);
    // }
    // printf("\n");
    return rc;
 }
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Puts num cryptographically strong pseudo-random bytes into buf.
// It will return an error if the PRNG has not been seeded with enough randomness
// to ensure an unpredictable byte sequence.
// In which case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	rv := C.GenerateRandomBytes((*C.byte)(unsafe.Pointer(&buf[0])), C.int(n))
	if rv != 1 {
		return nil, fmt.Errorf("Unable to GenerateRandomBytes")
	}
	return buf, nil
}