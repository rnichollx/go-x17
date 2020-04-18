// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hamsi

// #include "ghamsi.h"
import "C"

// SumBig creates a hamsi hash of the given bytes and returns always exactly 64 bytes.
func SumBig(inputData []byte) []byte {
	var hashOutput [64]C.char
	var returnBuffer [64]byte

	C.HashHamsi(C.CString(string(inputData)), &hashOutput[0])
	outputBuffer := []byte(C.GoStringN(&hashOutput[0], 64))

	copy(returnBuffer[:], outputBuffer)
	return returnBuffer[:]
}
