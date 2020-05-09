// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fugue

// #include "gfugue.h"
import "C"

// SumBig creates a hamsi hash of the given bytes and returns always exactly 64 bytes.
func SumBig(inputData []byte, dst []byte) {
	var hashOutput [64]C.char

	C.HashFugue(C.CString(string(inputData)), C.int(len(inputData)), &hashOutput[0])
	outputBuffer := []byte(C.GoStringN(&hashOutput[0], 64))

	copy(dst[:], outputBuffer)
}
