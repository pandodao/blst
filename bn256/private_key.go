package bn256

import (
	"encoding/hex"
	"strconv"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
)

func GenerateKey() *PrivateKey {
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().Pick(random.New())
	return &PrivateKey{Scalar: scalar}
}

func (key *PrivateKey) Sign(msg []byte) (*Signature, error) {
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	bts, err := scheme.Sign(key.Scalar, msg)
	if err != nil {
		return nil, err
	}

	suite := bn256.NewSuiteG1()
	point := suite.G1().Point()
	if err := point.UnmarshalBinary(bts); err != nil {
		return nil, err
	}

	var sig Signature
	err = sig.FromBytes(bts)
	return &sig, err
}

func (key *PrivateKey) PublicKey() *PublicKey {
	suite := bn256.NewSuiteG2()
	point := suite.Point().Mul(key.Scalar, nil)
	return &PublicKey{Point: point}
}

func (key *PrivateKey) Bytes() ([]byte, error) {
	return key.Scalar.MarshalBinary()
}

func (key *PrivateKey) FromBytes(bts []byte) error {
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().SetBytes(bts)
	key.Scalar = scalar
	return nil
}

func (key *PrivateKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(key.String())), nil
}

func (key *PrivateKey) UnmarshalJSON(b []byte) error {
	unquoted, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}

	bts, err := hex.DecodeString(unquoted)
	if err != nil {
		return err
	}

	return key.FromBytes(bts)
}
