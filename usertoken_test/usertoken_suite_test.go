package usertoken_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestUserToken(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "UserToken Suite")
}
