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
	blockHashSize      = 32
	checkHashBlockSize = 16
	userSecretSize     = 32
)

//Config : trustchain cofiguration
type Config struct {
	TrustchainID         string
	TrustchainPrivateKey string
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
	userID, err := hashUserID(trustchainID, userIDString)
	if err != nil {
		return "", err
	}

	userSecret, err2 := createUserSecret(userID)
	if err2 != nil {
		return "", err2
	}

	eprivSignKey, epubSignKey, _ := cryptosign.CryptoSignKeyPair()

	payload := append(epubSignKey, userID...)

	delegationSignature, err3 := sign(payload, trustchainPrivateKey)
	if err3 != nil {
		return "", err3
	}

	delegationToken := DelegationToken{
		DelegationSignature:          delegationSignature,
		EphemeralPrivateSignatureKey: eprivSignKey,
		EphemeralPublicSignatureKey:  epubSignKey,
		UserID:     userID,
		UserSecret: userSecret,
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

func hashUserID(trustchainID []byte, userIDString string) ([]byte, error) {
	userIDBuffer := append([]byte(userIDString), trustchainID...)
	hashedUserID, err := generichash.CryptoGenericHash(blockHashSize, userIDBuffer, nil)
	if err != 0 {
		return nil, errors.New("Could not hash: " + string(err))
	}
	return hashedUserID, nil
}

func createUserSecret(userID []byte) ([]byte, error) {
	rand := randombytes.RandomBytes(userSecretSize - 1)
	check, err := generichash.CryptoGenericHash(checkHashBlockSize, append(rand, userID...), nil)
	if err != 0 {
		return nil, errors.New("Could not hash: " + string(err))
	}
	return append(rand, check[0]), nil
}

func sign(payload []byte, signKey []byte) ([]byte, error) {
	signature, err := cryptosign.CryptoSignDetached(payload, signKey)
	if err != 0 {
		return nil, errors.New("Could not sign: " + string(err))
	}
	return signature, nil
}
