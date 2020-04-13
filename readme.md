# go-x11 [![License](https://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/marpme/go-x17/blob/master/license.md) [![godoc](https://img.shields.io/badge/go-documentation-blue.svg)](https://godoc.org/github.com/marpme/go-x17) [![Build Status](https://travis-ci.org/marpme/go-x17.svg?branch=master)](https://travis-ci.org/marpme/go-x17) [![Coverage Status](https://coveralls.io/repos/github/marpme/go-x17/badge.svg?branch=master)](https://coveralls.io/github/marpme/go-x17?branch=master)

Implements the x17 hash and required functions in go.

## Usage

```go
	package main

	import (
		"fmt"
		"github.com/marpme/go-x17"
	)

	func main() {
		hs, out := x11.New(), [32]byte{}
		hs.Hash([]byte("XVG"), out[:])
		fmt.Printf("%x \n", out[:])
	}
```

## Notes

Echo, Simd and Shavite do not have 100% test coverage, a full test on these
requires the test to hash a blob of bytes that is several gigabytes large.

## License

go-x17 is licensed under the [copyfree](http://copyfree.org) ISC license.
