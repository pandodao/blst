package bn256

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"

	"github.com/drand/kyber/pairing/bn256"
)

func (sig *Signature) Bytes() []byte {
	eb, err := sig.Point.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return eb
}

func (sig *Signature) Compress() []byte {
	eb := sig.Bytes()

	y := new(big.Int).SetBytes(eb[32:])

	// calculating the other possible solution of y²=x³+3
	y2 := new(big.Int).Sub(p, y)
	// if the specular solution is a bigger nr. we encode 0x00
	if y.Cmp(y2) < 0 {
		eb[32] = 0x00
	} else { // the specular solution is lower
		eb[32] = 0x01
	}

	//appending to X the information about which nr to pick for Y
	//if the smaller or the bigger
	return eb[0:33]
}

func (sig *Signature) String() string {
	return hex.EncodeToString(sig.Compress())
}

func (sig *Signature) FromBytes(bts []byte) error {
	if len(bts) == 33 {
		xi := new(big.Int).SetBytes(bts[:32])
		x3 := new(big.Int).Mul(xi, xi)
		x3 = x3.Mul(x3, xi)

		t := new(big.Int).Add(x3, big.NewInt(B))
		y1 := new(big.Int).ModSqrt(t, p)
		if y1 == nil {
			return errors.New("invalid signature")
		}
		y2 := new(big.Int).Sub(p, y1)
		smaller := y1.Cmp(y2) < 0
		if (bts[32] == 0x01 && smaller) || (bts[32] == 0x00 && !smaller) {
			y1 = y2
		}

		yb := y1.Bytes()
		paddingLength := 32 - len(yb)

		// instantiating the byte array representing G1
		g := make([]byte, 64)

		// copy X byte representation at the beginning of G1 reconstructed slice
		copy(g, bts[:32])

		// do we need padding?
		if paddingLength > 0 {
			// create a padding byte slice for Y byte representation to be 32 bytes
			padding := make([]byte, paddingLength)
			// padding goes at the head of the Y array
			copy(g[32:32+paddingLength], padding)
		}

		// copy the Y byte representation to G1
		copy(g[32+paddingLength:], yb)

		bts = g
	}

	if len(bts) != 64 {
		return errors.New("invalid signature length")
	}

	suite := bn256.NewSuiteG1()
	point := suite.G1().Point()
	err := point.UnmarshalBinary(bts)
	if err != nil {
		return err
	}

	sig.Point = point
	return nil
}

func (sig *Signature) MarshalBinary() ([]byte, error) {
	return sig.Compress(), nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	return sig.FromBytes(data)
}

func (sig *Signature) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(hex.EncodeToString(sig.Compress()))), nil
}

func (sig *Signature) UnmarshalJSON(b []byte) error {
	unquoted, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}

	bts, err := hex.DecodeString(unquoted)
	if err != nil {
		return err
	}

	return sig.FromBytes(bts)
}

func AggregateSignatures(sigs []*Signature) *Signature {
	var aggSig *Signature
	for _, s := range sigs {
		if aggSig == nil {
			aggSig = s
		} else {
			aggSig.Point.Add(aggSig.Point, s.Point)
		}
	}
	return aggSig
}
