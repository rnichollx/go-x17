// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package x17

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	hs := New()
	out := [32]byte{}

	for i := range tsInfo {
		ln := len(tsInfo[i].out)
		dest := make([]byte, ln)

		hs.Hash(tsInfo[i].in[:], out[:])
		if ln != hex.Encode(dest, out[:]) {
			t.Errorf("%s: invalid length", tsInfo[i])
		}
		// Test Print if necessary.
		// fmt.Printf("%s\n", dest)
		if !bytes.Equal(dest[:], tsInfo[i].out[:]) {
			t.Errorf("%s: invalid hash expected: %s, got: %s", tsInfo[i].id, tsInfo[i].out[:], dest[:])
		}
	}
}

////////////////

var tsInfo = []struct {
	id  string
	in  []byte
	out []byte
}{
	{
		"Empty",
		[]byte(""),
		[]byte("e81881125bc6ed9c99d7403daf8d23a25fc107110843754fdea5d81a1cf34344"),
	},
	{
		"Dash",
		[]byte("DASH"),
		[]byte("2be61b04480c95c86732066eb2918dd8957da36d8d77ee14194f265d76530e24"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("b1ad1118c01385dfed9f0a89801febe7a650202bd6a48151ba18e8b969f55d1a"),
	},
}
