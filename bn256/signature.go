package bn256

import (
	"encoding/hex"
	"strconv"

	"github.com/drand/kyber/pairing/bn256"
)

func (pub *Signature) Bytes() ([]byte, error) {
	return pub.Point.MarshalBinary()
}

func (pub *Signature) FromBytes(bts []byte) error {
	suite := bn256.NewSuiteG1()
	point := suite.G1().Point()
	err := point.UnmarshalBinary(bts)
	if err != nil {
		return err
	}

	pub.Point = point
	return nil
}

func (pub *Signature) MarshalJSON() ([]byte, error) {
	bts, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return []byte(strconv.Quote(hex.EncodeToString(bts))), nil
}

func (pub *Signature) UnmarshalJSON(b []byte) error {
	unquoted, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}

	bts, err := hex.DecodeString(unquoted)
	if err != nil {
		return err
	}

	return pub.FromBytes(bts)
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
