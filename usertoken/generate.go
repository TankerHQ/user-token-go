package usertoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	generichash "github.com/GoKillers/libsodium-go/cryptogenerichash"
	"github.com/GoKillers/libsodium-go/cryptosign"
	"github.com/GoKillers/libsodium-go/randombytes"
)

const (
	blockHashSize  = 32
	userSecretSize = 32
)

//Config : trustchain cofiguration
type Config struct {
	trustchainID         string
	trustchainPrivateKey string
}

//Generate a user token for given user.
func Generate(config Config, userID string) (string, error) {
	truschainIDBytes, err := base64.StdEncoding.DecodeString(config.trustchainID)
	if err != nil {
		return "", errors.New("Wrong trustchainID format, should be base64: " + config.trustchainID)
	}
	trustchainPrivKeyBytes, err := base64.StdEncoding.DecodeString(config.trustchainPrivateKey)
	if err != nil {
		return "", errors.New("Wrong trustchainPrivateKey format, should be base64: " + config.trustchainPrivateKey)
	}
	return generateToken(truschainIDBytes, trustchainPrivKeyBytes, userID)
}

type delegationToken struct {
	EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
	EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
	UserID                       []byte `json:"user_id"`
	DelegationSignature          []byte `json:"delegation_signature"`
	UserSecret                   []byte `json:"user_secret"`
}

func generateToken(trustchainID []byte, trustchainPrivateKey []byte,
	userIDString string) (string, error) {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	userID, err := generichash.CryptoGenericHash(blockHashSize, userIDBuffer, nil)
	if err != 0 {
		return "", errors.New("can't hash: " + string(err))
	}

	eprivSignKey, epubSignKey, _ := cryptosign.CryptoSignKeyPair()
	toSign := append(epubSignKey, userID...)
	delegationSignature, err2 := cryptosign.CryptoSignDetached(toSign, trustchainPrivateKey)
	if err2 != 0 {
		return "", errors.New("can't sign: " + string(err2))
	}

	rand := randombytes.RandomBytes(userSecretSize - 1)
	hashedStuff, err := generichash.CryptoGenericHash(blockHashSize, append(rand, userID...), nil)
	if err != 0 {
		return "", errors.New("Could not hash" + string(err))
	}
	userSecret := append(rand, hashedStuff...)

	delegationToken := delegationToken{
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserID:              userID,
		DelegationSignature: delegationSignature,
		UserSecret:          userSecret,
	}
	jsonToken, err3 := json.Marshal(delegationToken)
	if err3 != nil {
		return "", err3
	}
	b64Token := base64.StdEncoding.EncodeToString(jsonToken)
	return b64Token, nil
}
