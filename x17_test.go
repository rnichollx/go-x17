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

	out17 := [32]byte{}
	for i := range tsInfo {
		ln := len(tsInfo[i].out17)
		dest := make([]byte, ln)

		hs.Hash(tsInfo[i].in[:], out17[:])
		if ln != hex.Encode(dest, out17[:]) {
			t.Errorf("%s: invalid length", tsInfo[i])
		}

		if !bytes.Equal(dest[:], tsInfo[i].out17[:]) {
			t.Errorf("[%s-x17]: invalid hash \nexpected:	%64s, \ngot:		%64s", tsInfo[i].id, tsInfo[i].out17[:], dest[:])
		}
	}
}

////////////////

var hexBlockVerge, _ = hex.DecodeString("041800009a04d9dd22efb4c0e322d12260ac1a6168f0d9d6752c4ae7b0337baaa1b1fb512ffcb93e17d818095cd4194a1eb5272b5df34897456a2284ee4fd62aabda4538412a375e9501011b14ebd1a7")
var hexBlockVerge2, _ = hex.DecodeString("04180000e6db0c480eb762feec8f650ce44cfaebe4e6e2f4cecd403f386917df0d3f20871f27d82a01fa39b0f3e7ed2c08d2849a8ef70b04ba707124888bb7d12561a9108dff665d8fa80b1b01a9bc92")
var tsInfo = []struct {
	id    string
	in    []byte
	out17 []byte
}{
	{
		"Empty",
		[]byte(""),
		[]byte("537920b6f5354b10a5adb27c070d38058b1bdce070de338cf5034d7c3f0c3696"),
	},
	{
		"Verge Block",
		hexBlockVerge,
		[]byte("0000000000001626efc6afc18acee83b71fb78b7823d5235279a3138e79b272e"),
	},
	{
		"Verge Block2",
		hexBlockVerge2,
		[]byte("00000000000550a9ba39bf31637c29d318283d1b2e292f0db81d3ac166788a0e"),
	},
	{
		"Fox",
		[]byte("The quick brown fox jumps over the lazy dog"),
		[]byte("958399aafef85344daba789bd611b1bd143de215b358cfec64cadb5ba9727d1f"),
	},
}
