// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package x17

// #include "hashx17.h"
import "C"

// Hash the provided data, returning a slice of the [32]byte containing the resulting hash.
func Sum(data []byte) [32]byte {
	var cresstr [32]C.char
	var retbuf [32]byte
	C.hashx17(C.CString(string(data)), C.int(len(data)), &cresstr[0])
	copy(retbuf[:], []byte(C.GoStringN(&cresstr[0], 32)[:32]))
	return retbuf
}
