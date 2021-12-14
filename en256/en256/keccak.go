package en256

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

type (
	KeccakState interface {
		hash.Hash
		Read([]byte) (int, error)
	}
)

func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak256().(KeccakState)
}

func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}
