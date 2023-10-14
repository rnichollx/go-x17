// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package x17

import (
	"crypto/sha512"
	"encoding/binary"
	"log"

	"github.com/rnichollx/go-x17/blake"
	"github.com/rnichollx/go-x17/bmw"
	"github.com/rnichollx/go-x17/cubed"
	"github.com/rnichollx/go-x17/echo"
	"github.com/rnichollx/go-x17/fugue"
	"github.com/rnichollx/go-x17/groest"
	"github.com/rnichollx/go-x17/hamsi"
	"github.com/rnichollx/go-x17/hash"
	"github.com/rnichollx/go-x17/haval"
	"github.com/rnichollx/go-x17/jhash"
	"github.com/rnichollx/go-x17/keccak"
	"github.com/rnichollx/go-x17/luffa"
	"github.com/rnichollx/go-x17/shabal"
	"github.com/rnichollx/go-x17/shavite"
	"github.com/rnichollx/go-x17/simd"
	"github.com/rnichollx/go-x17/skein"
	"github.com/rnichollx/go-x17/whirlpool_x17"
)

////////////////

// Hash contains the state objects
// required to perform the x17.Hash.
type Hash struct {
	tha [64]byte
	thb [64]byte

	le [4]uint64

	blake   hash.Digest
	bmw     hash.Digest
	cubed   hash.Digest
	echo    hash.Digest
	groest  hash.Digest
	jhash   hash.Digest
	keccak  hash.Digest
	luffa   hash.Digest
	shavite hash.Digest
	simd    hash.Digest
	skein   hash.Digest
}

// New returns a new object to compute a x17 hash.
func New() *Hash {
	ref := &Hash{}
	ref.blake = blake.New()
	ref.bmw = bmw.New()
	ref.cubed = cubed.New()
	ref.echo = echo.New()
	ref.groest = groest.New()
	ref.jhash = jhash.New()
	ref.keccak = keccak.New()
	ref.luffa = luffa.New()
	ref.shavite = shavite.New()
	ref.simd = simd.New()
	ref.skein = skein.New()

	return ref
}

// Hash computes the hash from the src bytes and stores the result in dst.
func (ref *Hash) Hash(src []byte, dst []byte) {
	ta := ref.tha[:]
	tb := ref.thb[:]

	ref.blake.Write(src)
	ref.blake.Close(tb, 0, 0)

	ref.bmw.Write(tb)
	ref.bmw.Close(ta, 0, 0)

	ref.groest.Write(ta)
	ref.groest.Close(tb, 0, 0)

	ref.skein.Write(tb)
	ref.skein.Close(ta, 0, 0)

	ref.jhash.Write(ta)
	ref.jhash.Close(tb, 0, 0)

	ref.keccak.Write(tb)
	ref.keccak.Close(ta, 0, 0)

	ref.luffa.Write(ta)
	ref.luffa.Close(tb, 0, 0)

	ref.cubed.Write(tb)
	ref.cubed.Close(ta, 0, 0)

	ref.shavite.Write(ta)
	ref.shavite.Close(tb, 0, 0)

	ref.simd.Write(tb)
	ref.simd.Close(ta, 0, 0)

	ref.echo.Write(ta)
	ref.echo.Close(tb, 0, 0)

	hamsi.SumBig(tb, ta[:])

	fugue.SumBig(ta, tb[:])

	shabal.SumBig(tb, ta[:])

	whirlpool := whirlpool_x17.New()
	whirlpool.Write(ta)
	tb = whirlpool.Sum(nil)

	sha512Hash := sha512.Sum512(tb)
	ta = sha512Hash[:]

	haval256Hash := haval.New()
	haval256Hash.Update(ta, 0, len(ta))
	tb = haval256Hash.Digest()

	ref.convert32BytesToBE(tb)
	copy(dst, tb)
}

func (ref *Hash) convert32BytesToBE(hashedBytes []byte) {

	if len(hashedBytes) < 32 {
		log.Fatal("Expected at least 32 bytes to be converted into big endian.")
	}

	ref.le[0] = binary.LittleEndian.Uint64(hashedBytes[0:8])
	ref.le[1] = binary.LittleEndian.Uint64(hashedBytes[8:16])
	ref.le[2] = binary.LittleEndian.Uint64(hashedBytes[16:24])
	ref.le[3] = binary.LittleEndian.Uint64(hashedBytes[24:32])

	for i := 0; i < len(ref.le); i++ {
		binary.BigEndian.PutUint64(hashedBytes[i*8:(i+1)*8], ref.le[len(ref.le)-1-i])
	}
}
