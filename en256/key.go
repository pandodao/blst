package en256

import "github.com/drand/kyber"

type (
	PrivateKey struct {
		kyber.Scalar
	}

	PublicKey struct {
		kyber.Point
	}

	Signature struct {
		kyber.Point
	}
)
