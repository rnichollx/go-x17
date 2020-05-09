package haval

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestApi(t *testing.T) {
	dgst := New()

	testSuccess, hashed := dgst.SelfTest()
	if !testSuccess {
		t.Errorf("\nExpected: %s \nGot: %s", digestZero, hashed)
	}

	buffer := []byte("")
	dgst.Update(buffer, 0, len(buffer))
}

func TestFalse(t *testing.T) {
	dgst := New()
	var encodedHash = make([]byte, 64)
	hex.Encode(encodedHash[:], dgst.Digest())

	if !bytes.Equal(encodedHash[:], tsInfo[0].out[:]) {
		t.Errorf("\nExpected: %x \nGot: %x", tsInfo[0].out[:], encodedHash)
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
		[]byte("be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330"),
	},
}

func Test_flipBits(t *testing.T) {

	tests := []struct {
		name string
		bits uint32
		want uint32
	}{
		{
			"name",
			0,
			^uint32(0),
		},
		{
			"name",
			20,
			^uint32(20),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flipBits(tt.bits); got != tt.want {
				t.Errorf("flipBits() = %064b, want %064b", got, tt.want)
			}
		})
	}
}
