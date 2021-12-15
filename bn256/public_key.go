package bn256

import (
	"encoding/hex"
	"strconv"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
)

func (pub *PublicKey) Verify(msg []byte, s *Signature) bool {
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	if err := scheme.Verify(pub.Point, msg, s.Bytes()); err != nil {
		return false
	}
	return true
}

func (pub *PublicKey) Bytes() []byte {
	bts, err := pub.Point.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return bts
}

func (pub *PublicKey) String() string {
	return hex.EncodeToString(pub.Bytes())
}

func (pub *PublicKey) FromBytes(bts []byte) error {
	suite := bn256.NewSuiteG2()
	point := suite.G2().Point()
	err := point.UnmarshalBinary(bts)
	if err != nil {
		return err
	}

	pub.Point = point
	return nil
}

func (pub *PublicKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(hex.EncodeToString(pub.Bytes()))), nil
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
