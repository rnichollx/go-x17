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
			t.Errorf("%s: invalid hash", tsInfo[i].id)
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
		[]byte("528b9b84a5492b92e219c668bb3f069442e440c6db882bba7ba358597f602deb"),
	},
	{
		"Dash",
		[]byte("DASH"),
		[]byte("cc5881c1e5b54d13cdd9b4db8f0f1ef161c062010453845ca11345e27fde6cae"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("e1042242ad97ac8b648e58c9ab7d9096b08a22d91ac9397ba3990d5a0bdcd143"),
	},
}
