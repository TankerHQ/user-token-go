package identity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

const (
	userSecretSize = 32
)

//Config : trustchain cofiguration
type Config struct {
	TrustchainID         string
	TrustchainPrivateKey string
}

func oneByteGenericHash(input []byte) []byte {
	hash, err := blake2b.New(16, []byte{})
	if err != nil {
		panic("hash failed: " + err.Error())
	}
	hash.Write(input)
	return hash.Sum([]byte{})
}

func genericHash(input []byte) []byte {
	hash, err := blake2b.New256([]byte{})
	if err != nil {
		panic("hash failed: " + err.Error())
	}
	hash.Write(input)
	return hash.Sum([]byte{})
}

func toB64JSON(v interface{}) (string, error) {
	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err := json.Marshal(v)
	if err != nil {
		return "", err
	}

	b64Token := base64.StdEncoding.EncodeToString(jsonToken)
	return b64Token, nil
}

func fromB64JSON(b64 string, v interface{}) error {
	str, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	err = json.Unmarshal(str, v)
	if err != nil {
		return err
	}
	return nil
}

//Exported only to facilitate code testing (this shouldn't be needed in any app using this lib)
type Identity struct {
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	Target                       string `json:"target"`
	Value                        []byte `json:"value"`
	UserSecret                   []byte `json:"user_secret"`
	TrustchainID                 []byte `json:"trustchain_id"`
}

type PublicIdentity struct {
	TrustchainID []byte `json:"trustchain_id"`
	Target       string `json:"target"`
	Value        []byte `json:"value"`
}

//Create a user token for given user.
func Create(config Config, userID string) (string, error) {
	truschainIDBytes, err := base64.StdEncoding.DecodeString(config.TrustchainID)
	if err != nil {
		return "", errors.New("Wrong trustchainID format, should be base64: " + config.TrustchainID)
	}
	trustchainPrivKeyBytes, err2 := base64.StdEncoding.DecodeString(config.TrustchainPrivateKey)
	if err2 != nil {
		return "", errors.New("Wrong trustchainPrivateKey format, should be base64: " + config.TrustchainPrivateKey)
	}
	return generateToken(truschainIDBytes, trustchainPrivKeyBytes, userID)
}

func GetPublicIdentity(b64Identity string) (string, error) {
	identity := Identity{}
	err := fromB64JSON(b64Identity, &identity)
	if err != nil {
		return "", err
	}

	if identity.Target != "user" {
		return "", errors.New("unsupported identity target")
	}

	publicIdentity := PublicIdentity{
		TrustchainID: identity.TrustchainID,
		Target:       "user",
		Value:        identity.Value,
	}

	b64PublicIdentity, err := toB64JSON(publicIdentity)
	if err != nil {
		return "", err
	}

	return b64PublicIdentity, nil
}

func generateToken(trustchainID []byte, trustchainPrivateKey []byte,
	userIDString string) (string, error) {
	userID := hashUserID(trustchainID, userIDString)

	userSecret := createUserSecret(userID)

	eprivSignKey, epubSignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	payload := append(epubSignKey, userID...)

	delegationSignature := ed25519.Sign(trustchainPrivateKey, payload)

	identity := Identity{
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		Target:                       "user",
		Value:                        userID,
		UserSecret:                   userSecret,
		TrustchainID:                 trustchainID,
	}

	b64Token, err := toB64JSON(identity)
	if err != nil {
		return "", err
	}
	return b64Token, nil
}

func hashUserID(trustchainID []byte, userIDString string) []byte {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	hashedUserID := genericHash(userIDBuffer)
	return hashedUserID
}

func createUserSecret(userID []byte) []byte {
	randdata := make([]byte, userSecretSize-1)
	rand.Read(randdata)
	check := oneByteGenericHash(append(randdata, userID...))
	return append(randdata, check[0])
}
