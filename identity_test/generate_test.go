package identity_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/TankerHQ/identity-go/identity"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

func checkDelegationSignature(identity identity.Identity, trustchainPublicKey []byte) {
	signedData := append(
		identity.EphemeralPublicSignatureKey,
		identity.Value...)

	Expect(ed25519.Verify(
		trustchainPublicKey,
		signedData,
		identity.DelegationSignature,
	)).To(Equal(true))
}

var _ = Describe("Hash", func() {
	It("should match the RFC7693 BLAKE2b-512 test vector for \"abc\"", func() {
		// To check that the hash function is implemented correctly, we compute a test vector,
		// which is a known expected output for a given input, defined in the standard
		hexVector := "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"
		vector, _ := hex.DecodeString(hexVector)
		input := []byte("abc")

		hash, err := blake2b.New512([]byte{})
		if err != nil {
			panic("hash failed: " + err.Error())
		}
		hash.Write(input)
		output := hash.Sum([]byte{})
		Expect(output).To(Equal(vector))
	})
})

var _ = Describe("Generate", func() {
	const (
		goodIdentity       = "eyJ0cnVzdGNoYWluX2lkIjoidHBveHlOemgwaFU5RzJpOWFnTXZIeXlkK3BPNnpHQ2pPOUJmaHJDTGpkND0iLCJ0YXJnZXQiOiJ1c2VyIiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSIsImRlbGVnYXRpb25fc2lnbmF0dXJlIjoiVTlXUW9sQ3ZSeWpUOG9SMlBRbWQxV1hOQ2kwcW1MMTJoTnJ0R2FiWVJFV2lyeTUya1d4MUFnWXprTHhINmdwbzNNaUE5cisremhubW9ZZEVKMCtKQ3c9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlhoM2kweERUcHIzSFh0QjJRNTE3UUt2M2F6TnpYTExYTWRKRFRTSDRiZDQ9IiwiZXBoZW1lcmFsX3ByaXZhdGVfc2lnbmF0dXJlX2tleSI6ImpFRFQ0d1FDYzFERndvZFhOUEhGQ2xuZFRQbkZ1Rm1YaEJ0K2lzS1U0WnBlSGVMVEVOT212Y2RlMEhaRG5YdEFxL2RyTTNOY3N0Y3gwa05OSWZodDNnPT0iLCJ1c2VyX3NlY3JldCI6IjdGU2YvbjBlNzZRVDNzMERrdmV0UlZWSmhYWkdFak94ajVFV0FGZXh2akk9In0="
		goodPublicIdentity = "eyJ0YXJnZXQiOiJ1c2VyIiwidHJ1c3RjaGFpbl9pZCI6InRwb3h5TnpoMGhVOUcyaTlhZ012SHl5ZCtwTzZ6R0NqTzlCZmhyQ0xqZDQ9IiwidmFsdWUiOiJSRGEwZXE0WE51ajV0VjdoZGFwak94aG1oZVRoNFFCRE5weTRTdnk5WG9rPSJ9"

		userID = "b_eich"
	)

	var (
		trustchainConfig = identity.Config{
			TrustchainID:         "tpoxyNzh0hU9G2i9agMvHyyd+pO6zGCjO9BfhrCLjd4=",
			TrustchainPrivateKey: "cTMoGGUKhwN47ypq4xAXAtVkNWeyUtMltQnYwJhxWYSvqjPVGmXd2wwa7y17QtPTZhn8bxb015CZC/e4ZI7+MQ==",
		}
		obfuscatedUserID, _    = base64.StdEncoding.DecodeString("RDa0eq4XNuj5tV7hdapjOxhmheTh4QBDNpy4Svy9Xok=")
		trustchainID, _        = base64.StdEncoding.DecodeString(trustchainConfig.TrustchainID)
		userSecret, _          = base64.StdEncoding.DecodeString("7FSf/n0e76QT3s0DkvetRVVJhXZGEjOxj5EWAFexvjI=")
		publicSignatureKey, _  = base64.StdEncoding.DecodeString("Xh3i0xDTpr3HXtB2Q517QKv3azNzXLLXMdJDTSH4bd4=")
		privateSignatureKey, _ = base64.StdEncoding.DecodeString("jEDT4wQCc1DFwodXNPHFClndTPnFuFmXhBt+isKU4ZpeHeLTENOmvcde0HZDnXtAq/drM3Ncstcx0kNNIfht3g==")
		delegationSignature, _ = base64.StdEncoding.DecodeString("U9WQolCvRyjT8oR2PQmd1WXNCi0qmL12hNrtGabYREWiry52kWx1AgYzkLxH6gpo3MiA9r++zhnmoYdEJ0+JCw==")
		trustchainPublicKey, _ = base64.StdEncoding.DecodeString("r6oz1Rpl3dsMGu8te0LT02YZ/G8W9NeQmQv3uGSO/jE=")
	)

	It("returns a tanker identity", func() {
		b64Identity, err := identity.Create(trustchainConfig, userID)
		Expect(err).To(Not(HaveOccurred()))

		sidentity, err := base64.StdEncoding.DecodeString(b64Identity)
		Expect(err).To(Not(HaveOccurred()))
		identity := identity.Identity{}
		err = json.Unmarshal(sidentity, &identity)
		Expect(err).To(Not(HaveOccurred()))

		Expect(identity.TrustchainID).To(Equal(trustchainID))
		Expect(identity.Target).To(Equal("user"))
		Expect(identity.Value).To(Equal(obfuscatedUserID))
		checkDelegationSignature(identity, trustchainPublicKey)
	})

	It("returns a tanker public identity from an tanker indentity", func() {
		id, err := identity.Create(trustchainConfig, userID)
		Expect(err).To(Not(HaveOccurred()))
		b64Identity, err := identity.GetPublicIdentity(id)
		Expect(err).To(Not(HaveOccurred()))

		sidentity, err := base64.StdEncoding.DecodeString(b64Identity)
		Expect(err).To(Not(HaveOccurred()))
		publicIdentity := identity.PublicIdentity{}
		err = json.Unmarshal(sidentity, &publicIdentity)
		Expect(err).To(Not(HaveOccurred()))

		Expect(publicIdentity.TrustchainID).To(Equal(trustchainID))
		Expect(publicIdentity.Target).To(Equal("user"))
		Expect(publicIdentity.Value).To(Equal(obfuscatedUserID))
	})

	It("parse a valid identity", func() {
		sidentity, err := base64.StdEncoding.DecodeString(goodIdentity)
		Expect(err).To(Not(HaveOccurred()))
		id := identity.Identity{}
		err = json.Unmarshal(sidentity, &id)
		Expect(err).To(Not(HaveOccurred()))

		Expect(id.TrustchainID).To(Equal(trustchainID))
		Expect(id.Target).To(Equal("user"))
		Expect(id.UserSecret).To(Equal(userSecret))
		Expect(id.EphemeralPublicSignatureKey).To(Equal(publicSignatureKey))
		Expect(id.EphemeralPrivateSignatureKey).To(Equal(privateSignatureKey))
		Expect(id.DelegationSignature).To(Equal(delegationSignature))
		Expect(id.Value).To(Equal(obfuscatedUserID))
	})

	It("parse a valid public identity", func() {
		sidentity, err := base64.StdEncoding.DecodeString(goodPublicIdentity)
		Expect(err).To(Not(HaveOccurred()))
		publicIdentity := identity.PublicIdentity{}
		err = json.Unmarshal(sidentity, &publicIdentity)
		Expect(err).To(Not(HaveOccurred()))

		Expect(publicIdentity.TrustchainID).To(Equal(trustchainID))
		Expect(publicIdentity.Target).To(Equal("user"))
		Expect(publicIdentity.Value).To(Equal(obfuscatedUserID))
	})
})
