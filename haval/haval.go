package haval

import (
	"encoding/hex"
)

const haval256Bits = int(32)
const havalVersion = int(1)
const haval3Round = int(3)
const haval4Round = int(4)
const haval5Round = int(5)

const blockSize = int(128) // inner block size in bytes

const digestZero = string("be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330")

type Haval256 struct {
	rounds   int
	h0       uint32
	h1       uint32
	h2       uint32
	h3       uint32
	h4       uint32
	h5       uint32
	h6       uint32
	h7       uint32
	hashSize int
	buffer   []byte
	count    int
}

func New() *Haval256 {
	ref := &Haval256{}
	ref.rounds = haval5Round
	ref.hashSize = haval256Bits
	ref.buffer = make([]byte, blockSize)

	ref.resetContext()

	return ref
}

func (ref *Haval256) SelfTest() (bool, []byte) {
	sourceHash := New().Digest()
	out := make([]byte, 64)
	hex.Encode(out, sourceHash[:])
	return digestZero == string(out), out
}

func (ref *Haval256) padBuffer() []byte {
	// pad out to 118 mod 128.  other 10 bytes have special use.
	n := int(ref.count % blockSize)
	padding := getInitialPadding(n)
	result := make([]byte, padding+10)
	result[0] = byte(0x01)

	// save the version number (LSB 3), the number of rounds (3 bits in the
	// middle), the fingerprint length (MSB 2 bits and next byte) and the
	// number of bits in the unpadded message.
	var bl = ref.hashSize * 8
	result[padding] = byte(((bl & 0x03) << 6) | ((ref.rounds & 0x07) << 3) | (havalVersion & 0x07))
	padding++
	result[padding] = byte(bl >> 2)
	padding++

	// save number of bits, casting the long to an array of 8 bytes
	var bits = uint64(ref.count << 3)
	result[padding] = byte(bits)
	padding++
	result[padding] = byte(bits >> 8)
	padding++
	result[padding] = byte(bits >> 16)
	padding++
	result[padding] = byte(bits >> 24)
	padding++
	result[padding] = byte(bits >> 32)
	padding++
	result[padding] = byte(bits >> 40)
	padding++
	result[padding] = byte(bits >> 48)
	padding++
	result[padding] = byte(bits >> 56)

	return result
}

func (ref *Haval256) Update(b []byte, offset int, len int) {
	n := int(ref.count % blockSize)
	ref.count += len
	partLen := blockSize - n
	i := 0

	if len >= partLen {
		copy(ref.buffer[n:(n+partLen)], b[offset:(offset+partLen)])
		ref.transform(ref.buffer, 0)
		for i = partLen; i+blockSize-1 < len; i += blockSize {
			ref.transform(b, offset+i)
		}
		n = 0
	}

	if i < len {
		copy(ref.buffer[n:(n+len-i)], b[(offset+i):(offset+i+len-i)])
	}
}

func (ref *Haval256) Digest() []byte {
	var tail = ref.padBuffer()     // pad remaining bytes in buffer
	ref.Update(tail, 0, len(tail)) // last transform of a message
	result := ref.getResult()      // make a result out of context

	ref.Reset() // reset this instance for future re-use

	return result
}

func (ref *Haval256) Reset() { // reset this instance for future re-use
	ref.count = 0
	for i := 0; i < blockSize; i++ {
		ref.buffer[i] = byte(0)
	}

	ref.resetContext()
}

func (ref *Haval256) resetContext() {
	ref.h0 = 0x243F6A88
	ref.h1 = 0x85A308D3
	ref.h2 = 0x13198A2E
	ref.h3 = 0x03707344
	ref.h4 = 0xA4093822
	ref.h5 = 0x299F31D0
	ref.h6 = 0x082EFA98
	ref.h7 = 0xEC4E6C89
}

func (ref *Haval256) getResult() []byte {
	result := make([]byte, ref.hashSize)
	result[31] = uint8(ref.h7 >> 24)
	result[30] = uint8(ref.h7 >> 16)
	result[29] = uint8(ref.h7 >> 8)
	result[28] = uint8(ref.h7)

	result[27] = uint8(ref.h6 >> 24)
	result[26] = uint8(ref.h6 >> 16)
	result[25] = uint8(ref.h6 >> 8)
	result[24] = uint8(ref.h6)

	result[23] = uint8(ref.h5 >> 24)
	result[22] = uint8(ref.h5 >> 16)
	result[21] = uint8(ref.h5 >> 8)
	result[20] = uint8(ref.h5)

	result[19] = uint8(ref.h4 >> 24)
	result[18] = uint8(ref.h4 >> 16)
	result[17] = uint8(ref.h4 >> 8)
	result[16] = uint8(ref.h4)

	result[15] = uint8(ref.h3 >> 24)
	result[14] = uint8(ref.h3 >> 16)
	result[13] = uint8(ref.h3 >> 8)
	result[12] = uint8(ref.h3)

	result[11] = uint8(ref.h2 >> 24)
	result[10] = uint8(ref.h2 >> 16)
	result[9] = uint8(ref.h2 >> 8)
	result[8] = uint8(ref.h2)

	result[7] = uint8(ref.h1 >> 24)
	result[6] = uint8(ref.h1 >> 16)
	result[5] = uint8(ref.h1 >> 8)
	result[4] = uint8(ref.h1)

	result[3] = uint8(ref.h0 >> 24)
	result[2] = uint8(ref.h0 >> 16)
	result[1] = uint8(ref.h0 >> 8)
	result[0] = uint8(ref.h0)

	return result
}

func (ref *Haval256) readInBytesTouint32(in []byte, i int) (uint32, int) {
	return uint32(in[i]&0xFF) | uint32(in[i+1]&0xFF)<<8 | uint32(in[i+2]&0xFF)<<16 | uint32(in[i+3]&0xFF)<<24, i + 4
}

func (ref *Haval256) transform(in []byte, i int) {
	X0, i := ref.readInBytesTouint32(in, i)
	X1, i := ref.readInBytesTouint32(in, i)
	X2, i := ref.readInBytesTouint32(in, i)
	X3, i := ref.readInBytesTouint32(in, i)
	X4, i := ref.readInBytesTouint32(in, i)
	X5, i := ref.readInBytesTouint32(in, i)
	X6, i := ref.readInBytesTouint32(in, i)
	X7, i := ref.readInBytesTouint32(in, i)
	X8, i := ref.readInBytesTouint32(in, i)
	X9, i := ref.readInBytesTouint32(in, i)
	X10, i := ref.readInBytesTouint32(in, i)
	X11, i := ref.readInBytesTouint32(in, i)
	X12, i := ref.readInBytesTouint32(in, i)
	X13, i := ref.readInBytesTouint32(in, i)
	X14, i := ref.readInBytesTouint32(in, i)
	X15, i := ref.readInBytesTouint32(in, i)
	X16, i := ref.readInBytesTouint32(in, i)
	X17, i := ref.readInBytesTouint32(in, i)
	X18, i := ref.readInBytesTouint32(in, i)
	X19, i := ref.readInBytesTouint32(in, i)
	X20, i := ref.readInBytesTouint32(in, i)
	X21, i := ref.readInBytesTouint32(in, i)
	X22, i := ref.readInBytesTouint32(in, i)
	X23, i := ref.readInBytesTouint32(in, i)
	X24, i := ref.readInBytesTouint32(in, i)
	X25, i := ref.readInBytesTouint32(in, i)
	X26, i := ref.readInBytesTouint32(in, i)
	X27, i := ref.readInBytesTouint32(in, i)
	X28, i := ref.readInBytesTouint32(in, i)
	X29, i := ref.readInBytesTouint32(in, i)
	X30, i := ref.readInBytesTouint32(in, i)
	X31, i := ref.readInBytesTouint32(in, i)

	t0 := ref.h0
	t1 := ref.h1
	t2 := ref.h2
	t3 := ref.h3
	t4 := ref.h4
	t5 := ref.h5
	t6 := ref.h6
	t7 := ref.h7

	// Pass 1
	t7 = ref.ff1(t7, t6, t5, t4, t3, t2, t1, t0, X0)
	t6 = ref.ff1(t6, t5, t4, t3, t2, t1, t0, t7, X1)
	t5 = ref.ff1(t5, t4, t3, t2, t1, t0, t7, t6, X2)
	t4 = ref.ff1(t4, t3, t2, t1, t0, t7, t6, t5, X3)
	t3 = ref.ff1(t3, t2, t1, t0, t7, t6, t5, t4, X4)
	t2 = ref.ff1(t2, t1, t0, t7, t6, t5, t4, t3, X5)
	t1 = ref.ff1(t1, t0, t7, t6, t5, t4, t3, t2, X6)
	t0 = ref.ff1(t0, t7, t6, t5, t4, t3, t2, t1, X7)

	t7 = ref.ff1(t7, t6, t5, t4, t3, t2, t1, t0, X8)
	t6 = ref.ff1(t6, t5, t4, t3, t2, t1, t0, t7, X9)
	t5 = ref.ff1(t5, t4, t3, t2, t1, t0, t7, t6, X10)
	t4 = ref.ff1(t4, t3, t2, t1, t0, t7, t6, t5, X11)
	t3 = ref.ff1(t3, t2, t1, t0, t7, t6, t5, t4, X12)
	t2 = ref.ff1(t2, t1, t0, t7, t6, t5, t4, t3, X13)
	t1 = ref.ff1(t1, t0, t7, t6, t5, t4, t3, t2, X14)
	t0 = ref.ff1(t0, t7, t6, t5, t4, t3, t2, t1, X15)

	t7 = ref.ff1(t7, t6, t5, t4, t3, t2, t1, t0, X16)
	t6 = ref.ff1(t6, t5, t4, t3, t2, t1, t0, t7, X17)
	t5 = ref.ff1(t5, t4, t3, t2, t1, t0, t7, t6, X18)
	t4 = ref.ff1(t4, t3, t2, t1, t0, t7, t6, t5, X19)
	t3 = ref.ff1(t3, t2, t1, t0, t7, t6, t5, t4, X20)
	t2 = ref.ff1(t2, t1, t0, t7, t6, t5, t4, t3, X21)
	t1 = ref.ff1(t1, t0, t7, t6, t5, t4, t3, t2, X22)
	t0 = ref.ff1(t0, t7, t6, t5, t4, t3, t2, t1, X23)

	t7 = ref.ff1(t7, t6, t5, t4, t3, t2, t1, t0, X24)
	t6 = ref.ff1(t6, t5, t4, t3, t2, t1, t0, t7, X25)
	t5 = ref.ff1(t5, t4, t3, t2, t1, t0, t7, t6, X26)
	t4 = ref.ff1(t4, t3, t2, t1, t0, t7, t6, t5, X27)
	t3 = ref.ff1(t3, t2, t1, t0, t7, t6, t5, t4, X28)
	t2 = ref.ff1(t2, t1, t0, t7, t6, t5, t4, t3, X29)
	t1 = ref.ff1(t1, t0, t7, t6, t5, t4, t3, t2, X30)
	t0 = ref.ff1(t0, t7, t6, t5, t4, t3, t2, t1, X31)

	// Pass 2
	t7 = ref.ff2(t7, t6, t5, t4, t3, t2, t1, t0, X5, 0x452821E6)
	t6 = ref.ff2(t6, t5, t4, t3, t2, t1, t0, t7, X14, 0x38D01377)
	t5 = ref.ff2(t5, t4, t3, t2, t1, t0, t7, t6, X26, 0xBE5466CF)
	t4 = ref.ff2(t4, t3, t2, t1, t0, t7, t6, t5, X18, 0x34E90C6C)
	t3 = ref.ff2(t3, t2, t1, t0, t7, t6, t5, t4, X11, 0xC0AC29B7)
	t2 = ref.ff2(t2, t1, t0, t7, t6, t5, t4, t3, X28, 0xC97C50DD)
	t1 = ref.ff2(t1, t0, t7, t6, t5, t4, t3, t2, X7, 0x3F84D5B5)
	t0 = ref.ff2(t0, t7, t6, t5, t4, t3, t2, t1, X16, 0xB5470917)

	t7 = ref.ff2(t7, t6, t5, t4, t3, t2, t1, t0, X0, 0x9216D5D9)
	t6 = ref.ff2(t6, t5, t4, t3, t2, t1, t0, t7, X23, 0x8979FB1B)
	t5 = ref.ff2(t5, t4, t3, t2, t1, t0, t7, t6, X20, 0xD1310BA6)
	t4 = ref.ff2(t4, t3, t2, t1, t0, t7, t6, t5, X22, 0x98DFB5AC)
	t3 = ref.ff2(t3, t2, t1, t0, t7, t6, t5, t4, X1, 0x2FFD72DB)
	t2 = ref.ff2(t2, t1, t0, t7, t6, t5, t4, t3, X10, 0xD01ADFB7)
	t1 = ref.ff2(t1, t0, t7, t6, t5, t4, t3, t2, X4, 0xB8E1AFED)
	t0 = ref.ff2(t0, t7, t6, t5, t4, t3, t2, t1, X8, 0x6A267E96)

	t7 = ref.ff2(t7, t6, t5, t4, t3, t2, t1, t0, X30, 0xBA7C9045)
	t6 = ref.ff2(t6, t5, t4, t3, t2, t1, t0, t7, X3, 0xF12C7F99)
	t5 = ref.ff2(t5, t4, t3, t2, t1, t0, t7, t6, X21, 0x24A19947)
	t4 = ref.ff2(t4, t3, t2, t1, t0, t7, t6, t5, X9, 0xB3916CF7)
	t3 = ref.ff2(t3, t2, t1, t0, t7, t6, t5, t4, X17, 0x0801F2E2)
	t2 = ref.ff2(t2, t1, t0, t7, t6, t5, t4, t3, X24, 0x858EFC16)
	t1 = ref.ff2(t1, t0, t7, t6, t5, t4, t3, t2, X29, 0x636920D8)
	t0 = ref.ff2(t0, t7, t6, t5, t4, t3, t2, t1, X6, 0x71574E69)

	t7 = ref.ff2(t7, t6, t5, t4, t3, t2, t1, t0, X19, 0xA458FEA3)
	t6 = ref.ff2(t6, t5, t4, t3, t2, t1, t0, t7, X12, 0xF4933D7E)
	t5 = ref.ff2(t5, t4, t3, t2, t1, t0, t7, t6, X15, 0x0D95748F)
	t4 = ref.ff2(t4, t3, t2, t1, t0, t7, t6, t5, X13, 0x728EB658)
	t3 = ref.ff2(t3, t2, t1, t0, t7, t6, t5, t4, X2, 0x718BCD58)
	t2 = ref.ff2(t2, t1, t0, t7, t6, t5, t4, t3, X25, 0x82154AEE)
	t1 = ref.ff2(t1, t0, t7, t6, t5, t4, t3, t2, X31, 0x7B54A41D)
	t0 = ref.ff2(t0, t7, t6, t5, t4, t3, t2, t1, X27, 0xC25A59B5)

	// Pass 3
	t7 = ref.ff3(t7, t6, t5, t4, t3, t2, t1, t0, X19, 0x9C30D539)
	t6 = ref.ff3(t6, t5, t4, t3, t2, t1, t0, t7, X9, 0x2AF26013)
	t5 = ref.ff3(t5, t4, t3, t2, t1, t0, t7, t6, X4, 0xC5D1B023)
	t4 = ref.ff3(t4, t3, t2, t1, t0, t7, t6, t5, X20, 0x286085F0)
	t3 = ref.ff3(t3, t2, t1, t0, t7, t6, t5, t4, X28, 0xCA417918)
	t2 = ref.ff3(t2, t1, t0, t7, t6, t5, t4, t3, X17, 0xB8DB38EF)
	t1 = ref.ff3(t1, t0, t7, t6, t5, t4, t3, t2, X8, 0x8E79DCB0)
	t0 = ref.ff3(t0, t7, t6, t5, t4, t3, t2, t1, X22, 0x603A180E)

	t7 = ref.ff3(t7, t6, t5, t4, t3, t2, t1, t0, X29, 0x6C9E0E8B)
	t6 = ref.ff3(t6, t5, t4, t3, t2, t1, t0, t7, X14, 0xB01E8A3E)
	t5 = ref.ff3(t5, t4, t3, t2, t1, t0, t7, t6, X25, 0xD71577C1)
	t4 = ref.ff3(t4, t3, t2, t1, t0, t7, t6, t5, X12, 0xBD314B27)
	t3 = ref.ff3(t3, t2, t1, t0, t7, t6, t5, t4, X24, 0x78AF2FDA)
	t2 = ref.ff3(t2, t1, t0, t7, t6, t5, t4, t3, X30, 0x55605C60)
	t1 = ref.ff3(t1, t0, t7, t6, t5, t4, t3, t2, X16, 0xE65525F3)
	t0 = ref.ff3(t0, t7, t6, t5, t4, t3, t2, t1, X26, 0xAA55AB94)

	t7 = ref.ff3(t7, t6, t5, t4, t3, t2, t1, t0, X31, 0x57489862)
	t6 = ref.ff3(t6, t5, t4, t3, t2, t1, t0, t7, X15, 0x63E81440)
	t5 = ref.ff3(t5, t4, t3, t2, t1, t0, t7, t6, X7, 0x55CA396A)
	t4 = ref.ff3(t4, t3, t2, t1, t0, t7, t6, t5, X3, 0x2AAB10B6)
	t3 = ref.ff3(t3, t2, t1, t0, t7, t6, t5, t4, X1, 0xB4CC5C34)
	t2 = ref.ff3(t2, t1, t0, t7, t6, t5, t4, t3, X0, 0x1141E8CE)
	t1 = ref.ff3(t1, t0, t7, t6, t5, t4, t3, t2, X18, 0xA15486AF)
	t0 = ref.ff3(t0, t7, t6, t5, t4, t3, t2, t1, X27, 0x7C72E993)

	t7 = ref.ff3(t7, t6, t5, t4, t3, t2, t1, t0, X13, 0xB3EE1411)
	t6 = ref.ff3(t6, t5, t4, t3, t2, t1, t0, t7, X6, 0x636FBC2A)
	t5 = ref.ff3(t5, t4, t3, t2, t1, t0, t7, t6, X21, 0x2BA9C55D)
	t4 = ref.ff3(t4, t3, t2, t1, t0, t7, t6, t5, X10, 0x741831F6)
	t3 = ref.ff3(t3, t2, t1, t0, t7, t6, t5, t4, X23, 0xCE5C3E16)
	t2 = ref.ff3(t2, t1, t0, t7, t6, t5, t4, t3, X11, 0x9B87931E)
	t1 = ref.ff3(t1, t0, t7, t6, t5, t4, t3, t2, X5, 0xAFD6BA33)
	t0 = ref.ff3(t0, t7, t6, t5, t4, t3, t2, t1, X2, 0x6C24CF5C)

	if ref.rounds >= 4 {
		t7 = ref.ff4(t7, t6, t5, t4, t3, t2, t1, t0, X24, 0x7A325381)
		t6 = ref.ff4(t6, t5, t4, t3, t2, t1, t0, t7, X4, 0x28958677)
		t5 = ref.ff4(t5, t4, t3, t2, t1, t0, t7, t6, X0, 0x3B8F4898)
		t4 = ref.ff4(t4, t3, t2, t1, t0, t7, t6, t5, X14, 0x6B4BB9AF)
		t3 = ref.ff4(t3, t2, t1, t0, t7, t6, t5, t4, X2, 0xC4BFE81B)
		t2 = ref.ff4(t2, t1, t0, t7, t6, t5, t4, t3, X7, 0x66282193)
		t1 = ref.ff4(t1, t0, t7, t6, t5, t4, t3, t2, X28, 0x61D809CC)
		t0 = ref.ff4(t0, t7, t6, t5, t4, t3, t2, t1, X23, 0xFB21A991)
		t7 = ref.ff4(t7, t6, t5, t4, t3, t2, t1, t0, X26, 0x487CAC60)
		t6 = ref.ff4(t6, t5, t4, t3, t2, t1, t0, t7, X6, 0x5DEC8032)
		t5 = ref.ff4(t5, t4, t3, t2, t1, t0, t7, t6, X30, 0xEF845D5D)
		t4 = ref.ff4(t4, t3, t2, t1, t0, t7, t6, t5, X20, 0xE98575B1)
		t3 = ref.ff4(t3, t2, t1, t0, t7, t6, t5, t4, X18, 0xDC262302)
		t2 = ref.ff4(t2, t1, t0, t7, t6, t5, t4, t3, X25, 0xEB651B88)
		t1 = ref.ff4(t1, t0, t7, t6, t5, t4, t3, t2, X19, 0x23893E81)
		t0 = ref.ff4(t0, t7, t6, t5, t4, t3, t2, t1, X3, 0xD396ACC5)

		t7 = ref.ff4(t7, t6, t5, t4, t3, t2, t1, t0, X22, 0x0F6D6FF3)
		t6 = ref.ff4(t6, t5, t4, t3, t2, t1, t0, t7, X11, 0x83F44239)
		t5 = ref.ff4(t5, t4, t3, t2, t1, t0, t7, t6, X31, 0x2E0B4482)
		t4 = ref.ff4(t4, t3, t2, t1, t0, t7, t6, t5, X21, 0xA4842004)
		t3 = ref.ff4(t3, t2, t1, t0, t7, t6, t5, t4, X8, 0x69C8F04A)
		t2 = ref.ff4(t2, t1, t0, t7, t6, t5, t4, t3, X27, 0x9E1F9B5E)
		t1 = ref.ff4(t1, t0, t7, t6, t5, t4, t3, t2, X12, 0x21C66842)
		t0 = ref.ff4(t0, t7, t6, t5, t4, t3, t2, t1, X9, 0xF6E96C9A)
		t7 = ref.ff4(t7, t6, t5, t4, t3, t2, t1, t0, X1, 0x670C9C61)
		t6 = ref.ff4(t6, t5, t4, t3, t2, t1, t0, t7, X29, 0xABD388F0)
		t5 = ref.ff4(t5, t4, t3, t2, t1, t0, t7, t6, X5, 0x6A51A0D2)
		t4 = ref.ff4(t4, t3, t2, t1, t0, t7, t6, t5, X15, 0xD8542F68)
		t3 = ref.ff4(t3, t2, t1, t0, t7, t6, t5, t4, X17, 0x960FA728)
		t2 = ref.ff4(t2, t1, t0, t7, t6, t5, t4, t3, X10, 0xAB5133A3)
		t1 = ref.ff4(t1, t0, t7, t6, t5, t4, t3, t2, X16, 0x6EEF0B6C)
		t0 = ref.ff4(t0, t7, t6, t5, t4, t3, t2, t1, X13, 0x137A3BE4)

		if ref.rounds == 5 {
			t7 = ref.ff5(t7, t6, t5, t4, t3, t2, t1, t0, X27, 0xBA3BF050)
			t6 = ref.ff5(t6, t5, t4, t3, t2, t1, t0, t7, X3, 0x7EFB2A98)
			t5 = ref.ff5(t5, t4, t3, t2, t1, t0, t7, t6, X21, 0xA1F1651D)
			t4 = ref.ff5(t4, t3, t2, t1, t0, t7, t6, t5, X26, 0x39AF0176)
			t3 = ref.ff5(t3, t2, t1, t0, t7, t6, t5, t4, X17, 0x66CA593E)
			t2 = ref.ff5(t2, t1, t0, t7, t6, t5, t4, t3, X11, 0x82430E88)
			t1 = ref.ff5(t1, t0, t7, t6, t5, t4, t3, t2, X20, 0x8CEE8619)
			t0 = ref.ff5(t0, t7, t6, t5, t4, t3, t2, t1, X29, 0x456F9FB4)

			t7 = ref.ff5(t7, t6, t5, t4, t3, t2, t1, t0, X19, 0x7D84A5C3)
			t6 = ref.ff5(t6, t5, t4, t3, t2, t1, t0, t7, X0, 0x3B8B5EBE)
			t5 = ref.ff5(t5, t4, t3, t2, t1, t0, t7, t6, X12, 0xE06F75D8)
			t4 = ref.ff5(t4, t3, t2, t1, t0, t7, t6, t5, X7, 0x85C12073)
			t3 = ref.ff5(t3, t2, t1, t0, t7, t6, t5, t4, X13, 0x401A449F)
			t2 = ref.ff5(t2, t1, t0, t7, t6, t5, t4, t3, X8, 0x56C16AA6)
			t1 = ref.ff5(t1, t0, t7, t6, t5, t4, t3, t2, X31, 0x4ED3AA62)
			t0 = ref.ff5(t0, t7, t6, t5, t4, t3, t2, t1, X10, 0x363F7706)

			t7 = ref.ff5(t7, t6, t5, t4, t3, t2, t1, t0, X5, 0x1BFEDF72)
			t6 = ref.ff5(t6, t5, t4, t3, t2, t1, t0, t7, X9, 0x429B023D)
			t5 = ref.ff5(t5, t4, t3, t2, t1, t0, t7, t6, X14, 0x37D0D724)
			t4 = ref.ff5(t4, t3, t2, t1, t0, t7, t6, t5, X30, 0xD00A1248)
			t3 = ref.ff5(t3, t2, t1, t0, t7, t6, t5, t4, X18, 0xDB0FEAD3)
			t2 = ref.ff5(t2, t1, t0, t7, t6, t5, t4, t3, X6, 0x49F1C09B)
			t1 = ref.ff5(t1, t0, t7, t6, t5, t4, t3, t2, X28, 0x075372C9)
			t0 = ref.ff5(t0, t7, t6, t5, t4, t3, t2, t1, X24, 0x80991B7B)

			t7 = ref.ff5(t7, t6, t5, t4, t3, t2, t1, t0, X2, 0x25D479D8)
			t6 = ref.ff5(t6, t5, t4, t3, t2, t1, t0, t7, X23, 0xF6E8DEF7)
			t5 = ref.ff5(t5, t4, t3, t2, t1, t0, t7, t6, X16, 0xE3FE501A)
			t4 = ref.ff5(t4, t3, t2, t1, t0, t7, t6, t5, X22, 0xB6794C3B)
			t3 = ref.ff5(t3, t2, t1, t0, t7, t6, t5, t4, X4, 0x976CE0BD)
			t2 = ref.ff5(t2, t1, t0, t7, t6, t5, t4, t3, X1, 0x04C006BA)
			t1 = ref.ff5(t1, t0, t7, t6, t5, t4, t3, t2, X25, 0xC1A94FB6)
			t0 = ref.ff5(t0, t7, t6, t5, t4, t3, t2, t1, X15, 0x409F60C4)
		}
	}

	ref.h7 += t7
	ref.h6 += t6
	ref.h5 += t5
	ref.h4 += t4
	ref.h3 += t3
	ref.h2 += t2
	ref.h1 += t1
	ref.h0 += t0
}

func (ref *Haval256) ff1(x7 uint32, x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32, w uint32) uint32 {
	var t uint32
	switch ref.rounds {
	case 3:
		t = ref.f1(x1, x0, x3, x5, x6, x2, x4)
		break
	case 4:
		t = ref.f1(x2, x6, x1, x4, x5, x3, x0)
		break
	default:
		t = ref.f1(x3, x4, x1, x0, x5, x2, x6)
	}
	return (t>>7 | t<<25) + (x7>>11 | x7<<21) + w
}

func (ref *Haval256) ff2(x7 uint32, x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32, w uint32, c uint32) uint32 {
	var t uint32
	switch ref.rounds {
	case 3:
		t = ref.f2(x4, x2, x1, x0, x5, x3, x6)
		break
	case 4:
		t = ref.f2(x3, x5, x2, x0, x1, x6, x4)
		break
	default:
		t = ref.f2(x6, x2, x1, x0, x3, x4, x5)
	}
	return (t>>7 | t<<25) + (x7>>11 | x7<<21) + w + c
}

func (ref *Haval256) ff3(x7 uint32, x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32, w uint32, c uint32) uint32 {
	var t uint32
	switch ref.rounds {
	case 3:
		t = ref.f3(x6, x1, x2, x3, x4, x5, x0)
		break
	case 4:
		t = ref.f3(x1, x4, x3, x6, x0, x2, x5)
		break
	default:
		t = ref.f3(x2, x6, x0, x4, x3, x1, x5)
	}
	return (t>>7 | t<<25) + (x7>>11 | x7<<21) + w + c
}

func (ref *Haval256) ff4(x7 uint32, x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32, w uint32, c uint32) uint32 {
	var t uint32
	switch ref.rounds {
	case 4:
		t = ref.f4(x6, x4, x0, x5, x2, x1, x3)
		break
	default:
		t = ref.f4(x1, x5, x3, x2, x0, x4, x6)
	}
	return (t>>7 | t<<25) + (x7>>11 | x7<<21) + w + c
}

func (ref *Haval256) ff5(x7 uint32, x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32, w uint32, c uint32) uint32 {
	t := ref.f5(x2, x5, x0, x6, x4, x3, x1)
	return (t>>7 | t<<25) + (x7>>11 | x7<<21) + w + c
}

func (ref *Haval256) f1(x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32) uint32 {
	return x1&(x0^x4) ^ x2&x5 ^ x3&x6 ^ x0
}

func (ref *Haval256) f2(x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32) uint32 {
	return x2&(x1&flipBits(x3)^x4&x5^x6^x0) ^ x4&(x1^x5) ^ x3&x5 ^ x0
}

func (ref *Haval256) f3(x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32) uint32 {
	return x3&(x1&x2^x6^x0) ^ x1&x4 ^ x2&x5 ^ x0
}

func (ref *Haval256) f4(x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32) uint32 {
	return x4&(x5&flipBits(x2)^x3&flipBits(x6)^x1^x6^x0) ^ x3&(x1&x2^x5^x6) ^ x2&x6 ^ x0
}

func (ref *Haval256) f5(x6 uint32, x5 uint32, x4 uint32, x3 uint32, x2 uint32, x1 uint32, x0 uint32) uint32 {
	return x0&(x1&x2&x3^flipBits(x5)) ^ x1&x4 ^ x2&x5 ^ x3&x6
}

func flipBits(bits uint32) uint32 {
	return (^bits)
}

func getInitialPadding(n int) int {
	if n < 118 {
		return 118 - n
	}

	return 246 - n
}
