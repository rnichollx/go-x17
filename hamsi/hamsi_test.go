// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package hamsi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	out := []byte{}

	for i := range tsInfo {
		length := len(tsInfo[i].out)
		destination := make([]byte, length)

		out = SumBig(tsInfo[i].in[:])
		hex.Encode(destination, out[:])

		if !bytes.Equal(destination[:], tsInfo[i].out[:]) {
			t.Errorf("%s: invalid hash expected: %s, got: %s", tsInfo[i].id, tsInfo[i].out[:], destination[:])
		}
	}
}

var tsInfo = []struct {
	id  string
	in  []byte
	out []byte
}{
	{
		"Empty",
		[]byte(""),
		[]byte("5cd7436a91e27fc809d7015c3407540633dab391127113ce6ba360f0c1e35f404510834a551610d6e871e75651ea381a8ba628af1dcf2b2be13af2eb6247290f"),
	},
	{
		"Dash",
		[]byte("DASH"),
		[]byte("0f3707039aa54520d8f6fe3b6a653601c64725ec608000a7269a0d96a6290f0cd9ce2008d2e272529b3cbd73f8fff9dc8df1fbec1682ed1835b606d6de114f83"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("d7453c84a10eab2d4eef9d8862ced59e0640fe0f3fb088812a8b71ac5ac68953b213492ce3d83415f22c7033573b66e28417da0cb728a18e8914e08140d0948c"),
	},
}

// func TestNistSum(t *testing.T) {
// 	for i := uint64(0); i < 2048; i++ {
// 		runNistSum(t, i)
// 	}
// }

// ////////////////

// func runNistSum(t *testing.T, idx uint64) {
// 	if extr := idx & 7; extr == 0 {
// 		rbuf := []byte{}
// 		dmsg := nist.Get(idx)

// 		rbuf = SumBig(dmsg)
// 		hash, _ := hex.DecodeString(NistResult[idx])

// 		if !nist.IsEqual(hash, rbuf[:]) {
// 			t.Errorf("\na) Sum %d:\n expected: %X\n      got: %X", idx, hash, rbuf[:])
// 		}

// 		rbuf = SumBig(dmsg)
// 		hash, _ = hex.DecodeString(NistResult[idx])

// 		if !nist.IsEqual(hash, rbuf[:]) {
// 			t.Errorf("\nb) Sum %d:\n expected: %X\n      got: %X", idx, hash, rbuf[:])
// 		}
// 	}
// }

// var NistResult = []string{
// 	"5cd7436a91e27fc809d7015c3407540633dab391127113ce6ba360f0c1e35f404510834a551610d6e871e75651ea381a8ba628af1dcf2b2be13af2eb6247290f",
// }
