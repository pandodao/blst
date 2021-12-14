package en256

import (
	"encoding/hex"
	"strconv"

	"github.com/pandodao/blst/en256/en256"
)

func (sig *Signature) Bytes() ([]byte, error) {
	return sig.Point.MarshalBinary()
}

func (sig *Signature) FromBytes(bts []byte) error {
	suite := en256.NewSuiteG1()
	point := suite.G1().Point()
	err := point.UnmarshalBinary(bts)
	if err != nil {
		return err
	}

	sig.Point = point
	return nil
}

func (sig *Signature) MarshalJSON() ([]byte, error) {
	bts, err := sig.Bytes()
	if err != nil {
		return nil, err
	}
	return []byte(strconv.Quote(hex.EncodeToString(bts))), nil
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
