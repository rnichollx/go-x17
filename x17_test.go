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
		[]byte("6db4782561b9d204ab5cafed83175a8198bb65e48722ffb997b36a13fc5fbe33"),
	},
	{
		"Dash",
		[]byte("DASH"),
		[]byte("917b3ee1904c019af5319f70c197a449711c9303d26bb942a5b2d1df71160b5f"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("fe8b334eaa56ddf2d29df1861f163af7241cf151d96e51d9ebd5f66b65661ae7"),
	},
}
