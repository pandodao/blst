package blst

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"

	blst "github.com/supranational/blst/bindings/go"
)

func GenerateKey() *PrivateKey {
	var (
		ikm = make([]byte, 32)
		s   = 0
	)

	for s < len(ikm) {
		n, _ := rand.Reader.Read(ikm[s:])
		s += n
	}

	return (*PrivateKey)(blst.KeyGen(ikm))
}

func (key *PrivateKey) Sign(msg []byte) *Signature {
	return (*Signature)(new(blst.P1Affine).Sign((*blst.SecretKey)(key), msg, dst))
}

func (key *PrivateKey) PublicKey() *PublicKey {
	pub := new(blst.P2Affine).From((*blst.SecretKey)(key))
	return (*PublicKey)(pub)
}

func (key *PrivateKey) Bytes() []byte {
	return (*blst.SecretKey)(key).Serialize()
}

func (key *PrivateKey) FromBytes(bts []byte) error {
	secret := new(blst.SecretKey).Deserialize(bts)
	if secret == nil {
		return fmt.Errorf("invalid blst private key")
	}

	*key = (PrivateKey)(*secret)
	return nil
}

func (key *PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

func (key *PrivateKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(key.String())), nil
}

func (key *PrivateKey) UnmarshalJSON(b []byte) error {
	unquoted, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}

	bts, err := base64.StdEncoding.DecodeString(unquoted)
	if err != nil {
		return err
	}

	return key.FromBytes(bts)
}
