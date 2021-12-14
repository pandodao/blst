package en256

import (
	"encoding/hex"
	"strconv"

	"github.com/drand/kyber/sign/bls"
	"github.com/pandodao/blst/en256/en256"
)

func (pub *PublicKey) Verify(msg []byte, s *Signature) bool {
	scheme := bls.NewSchemeOnG1(en256.NewSuiteG2())
	bts, err := s.Bytes()
	if err != nil {
		return false
	}
	if err := scheme.Verify(pub.Point, msg, bts); err != nil {
		return false
	}
	return true
}

func (pub *PublicKey) Bytes() ([]byte, error) {
	return pub.Point.MarshalBinary()
}

func (pub *PublicKey) FromBytes(bts []byte) error {
	suite := en256.NewSuiteG2()
	point := suite.G2().Point()
	err := point.UnmarshalBinary(bts)
	if err != nil {
		return err
	}

	pub.Point = point
	return nil
}

func (pub *PublicKey) MarshalJSON() ([]byte, error) {
	bts, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return []byte(strconv.Quote(hex.EncodeToString(bts))), nil
}

func (pub *PublicKey) UnmarshalJSON(b []byte) error {
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

func AggregatePublicKeys(pubs []*PublicKey) *PublicKey {
	var aggPub *PublicKey
	for _, p := range pubs {
		if aggPub == nil {
			aggPub = p
		} else {
			aggPub.Point.Add(aggPub.Point, p.Point)
		}
	}
	return aggPub
}
