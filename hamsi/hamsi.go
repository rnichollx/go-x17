// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hamsi

// #include "ghamsi.h"
import "C"
import "unsafe"

// SumBig creates a hamsi hash of the given bytes and returns always exactly 64 bytes.
func SumBig(inputData []byte, dst []byte) {
	var hashOutput [64]C.char

	C.HashHamsi(C.CString(string(inputData)), C.int(len(inputData)), &hashOutput[0])
	outputBuffer := C.GoBytes(unsafe.Pointer(&hashOutput[0]), 64)

	copy(dst[:], outputBuffer)
}
