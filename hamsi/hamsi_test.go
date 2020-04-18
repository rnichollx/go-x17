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
			t.Errorf("%s: invalid hash", tsInfo[i].id)
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
		[]byte("ff04c87d8deacce719c38c5ee2f8c9a17bb2c294bd280a51d52bbe187d783084bcfa5bd3f3eaaf1be9d4084acac5c40e4fad1b605828fd812ae08484a7bb2e89"),
	},
	{
		"Dash",
		[]byte("DASH"),
		[]byte("21cc135df44a8364ba31138f755fcbc5c89cc7eacbe2605fef6271fffe78b3b6ac60b1e0dfaa1b56b16b8900a2a9db9d847988b4b61568e61826ecc4b7295093"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("058e371dfbbf8744e19867f5a1ffb5e26196c3094f20a11e4e3eae88c67a4ddf712b3f682c23d2ab47e96de0a7241972fa49c26b5aaff9d88bb1d4519f687bce"),
	},
}
