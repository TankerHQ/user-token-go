package usertoken_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	generichash "github.com/GoKillers/libsodium-go/cryptogenerichash"
	"github.com/GoKillers/libsodium-go/cryptosign"
	"github.com/GoKillers/libsodium-go/randombytes"
	"github.com/SuperTanker/tanker-go/usertoken"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hash", func() {
	It("should match the RFC7693 BLAKE2b-512 test vector for \"abc\"", func() {
		// To check that the hash function is implemented correctly, we compute a test vector,
		// which is a known expected output for a given input, defined in the standard
		hexVector := "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"
		vector, _ := hex.DecodeString(hexVector)
		input := []byte("abc")
		output, _ := generichash.CryptoGenericHash(64, input, nil)
		Expect(output).To(Equal(vector))
	})
})

var _ = Describe("Generate", func() {
	It("returns a valid token signed with the trustchain private key", func() {
		config := usertoken.Config{
			TrustchainID:         "AzES0aJwDCej9bQVY9AUMZBCLdX0msEc/TJ4DOhZaQs=",
			TrustchainPrivateKey: "cBAq6A00rRNVTHicxNHdDFuq6LNUo6gAz58oKqy9CGd054sGkfPYgXftRCRLfqxeiaoRwQCNLIKxdnuKuf1RAA==",
		}
		trustchainPublicKey := "dOeLBpHz2IF37UQkS36sXomqEcEAjSyCsXZ7irn9UQA="
		userIDString := "user@tanker.io"

		b64Token, err := usertoken.Generate(config, userIDString)
		Expect(err).NotTo(HaveOccurred())

		jsonToken, err2 := base64.StdEncoding.DecodeString(b64Token)
		Expect(err2).NotTo(HaveOccurred())

		type delegationToken struct {
			EphemeralPublicSignatureKey  []byte `json:"ephemeral_public_signature_key"`
			EphemeralPrivateSignatureKey []byte `json:"ephemeral_private_signature_key"`
			UserID                       []byte `json:"user_id"`
			DelegationSignature          []byte `json:"delegation_signature"`
			UserSecret                   []byte `json:"user_secret"`
		}

		var token delegationToken

		// Note: base64-encoded strings values are automatically decoded as []byte
		//       thanks to the []byte typing in the delegationToken struct
		err3 := json.Unmarshal(jsonToken, &token)
		Expect(err3).NotTo(HaveOccurred())

		// check valid control byte in user secret
		Expect(len(token.UserID)).To(Equal(32))
		Expect(len(token.UserSecret)).To(Equal(32))
		payload := []byte{}
		payload = append(payload, token.UserSecret[:31]...)
		payload = append(payload, token.UserID...)
		control, code := generichash.CryptoGenericHash(16, payload, nil)
		Expect(code).To(Equal(0)) // means no error
		Expect(token.UserSecret[31]).To(Equal(control[0]))

		// check with valid signature
		payload = []byte{}
		payload = append(payload, token.EphemeralPublicSignatureKey...)
		payload = append(payload, token.UserID...)
		signKey, _ := base64.StdEncoding.DecodeString(trustchainPublicKey)
		Expect(cryptosign.CryptoSignVerifyDetached(token.DelegationSignature, payload, signKey)).To(Equal(0))

		// check with invalid signature
		signatureLength := len(token.DelegationSignature)
		invalidSignature := randombytes.RandomBytes(signatureLength)
		Expect(cryptosign.CryptoSignVerifyDetached(invalidSignature, payload, signKey)).NotTo(Equal(0))
	})
})
