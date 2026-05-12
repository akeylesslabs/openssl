// Copyright (C) 2017. See AUTHORS.
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

/*
#include <openssl/evp.h>
#include <openssl/provider.h>

static OSSL_PROVIDER *goopenssl_base_provider = NULL;
static OSSL_PROVIDER *goopenssl_fips_provider = NULL;

static int goopenssl_fips_mode_set(int mode) {
	if (mode) {
		if (goopenssl_base_provider == NULL) {
			goopenssl_base_provider = OSSL_PROVIDER_load(NULL, "base");
			if (goopenssl_base_provider == NULL) {
				return 0;
			}
		}
		if (goopenssl_fips_provider == NULL) {
			goopenssl_fips_provider = OSSL_PROVIDER_load(NULL, "fips");
			if (goopenssl_fips_provider == NULL) {
				return 0;
			}
		}
		return EVP_default_properties_enable_fips(NULL, 1);
	}
	return EVP_default_properties_enable_fips(NULL, 0);
}

static int goopenssl_fips_mode(void) {
	return EVP_default_properties_is_fips_enabled(NULL);
}
*/
import "C"
import (
	"runtime"
	"sync"
)

var fipsMu sync.Mutex

// FIPSModeSet enables or disables OpenSSL 3 FIPS default properties.
func FIPSModeSet(mode bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fipsMu.Lock()
	defer fipsMu.Unlock()

	if mode == FIPSMode() {
		return nil
	}
	var r C.int
	if mode {
		r = C.goopenssl_fips_mode_set(1)
	} else {
		r = C.goopenssl_fips_mode_set(0)
	}
	if r != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// FIPSMode returns whether OpenSSL 3 FIPS default properties are enabled.
func FIPSMode() bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	r := C.goopenssl_fips_mode()
	return r != 0
}
