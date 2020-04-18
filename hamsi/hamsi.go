// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hamsi

// #include "ghamsi.h"
import "C"

// Sum creates a hamsi hash of the given bytes and returns exactly 64 bytes.
func Sum(data []byte) []byte {
	var cresstr [64]C.char
	var retbuf []byte

	C.HashHamsi(C.CString(string(data)), C.int(len(data)), &cresstr[0])
	copy(retbuf[:], []byte(C.GoStringN(&cresstr[0], 64)[:64]))

	return retbuf
}
