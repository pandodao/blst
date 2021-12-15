package bn256

import "math/big"

const (
	// B is constant of the curve
	B = 3
)

var (
	// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
	p = bigFromBase10("65000549695646603732796438742359905742825358107623003571877145026864184071783")
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}
