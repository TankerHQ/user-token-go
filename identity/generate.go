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

//Generate a user token for given user.
func Generate(config Config, userID string) (string, error) {
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

//Exported only to facilitate code testing (this shouldn't be needed in any app using this lib)
type DelegationToken struct {
	DelegationSignature          []byte `json:"delegation_signature"`
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserID                       []byte `json:"user_id"`
	UserSecret                   []byte `json:"user_secret"`
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

	delegationToken := DelegationToken{
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserID:                       userID,
		UserSecret:                   userSecret,
	}

	// Note: []byte values are encoded as base64-encoded strings
	//       (see: https://golang.org/pkg/encoding/json/#Marshal)
	jsonToken, err4 := json.Marshal(delegationToken)
	if err4 != nil {
		return "", err4
	}

	b64Token := base64.StdEncoding.EncodeToString(jsonToken)
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
