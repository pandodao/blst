package en256

import (
	"math/big"
)

const (
	// B is constant of the curve
	B = 3
)

var (
	// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
	p = bigFromBase10("21888242871839275222246405745257275088696311157297823662689037894645226208583")
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}
