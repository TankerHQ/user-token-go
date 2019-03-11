# User token [![Travis][build-badge]][build]

User token generation in Go for the [Tanker SDK](https://tanker.io/docs/latest).

## Installation

```bash
go get github.com/TankerHQ/identity-go/identity
```

This library depends on [libsodium](https://download.libsodium.org/doc/) and [libsodium-go](https://github.com/GoKillers/libsodium-go).

As a setup example, you can check the [ci/install.sh](https://github.com/TankerHQ/identity-go/blob/master/ci/install.sh) script we use to run tests in Travis.

## Usage

The server-side code below demonstrates a typical flow to safely deliver user tokens to your users:

```go
import (
    "github.com/TankerHQ/identity-go/identity"
)

config := identity.Config {
    TrustchainID: "<trustchain-id>",
    TrustchainPrivateKey: "<trustchain-private-key>",
}

// Example server-side function in which you would implement checkAuth(),
// retrieveIdentity() and storeIdentity() to use your own authentication
// and data storage mechanisms:
func getIdentity(string userID) (string, error) {
    isAuthenticated := checkAuth(userID)

    // Always ensure userID is authenticated before returning a user token
    if ! isAuthenticated {
      return "", error.New("Unauthorized")
    }

    // Retrieve a previously stored user token for this user
    identity := retrieveIdentity(userID)

    // If not found, create a new user token
    if identity == "" {
        identity, err = identity.Generate(config, userID)
        if err != nil {
            return "", err
        }

        // Store the newly generated user token
        storeIdentity(userID, identity)
    }

    // From now, the same user token will always be returned to a given user
    return identity, nil
}
```

Read more about user tokens in the [Tanker guide](https://tanker.io/docs/latest/guide/server/).

## Development

Run tests:

```bash
go test ./... -test.v
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/TankerHQ/identity-go.

[build-badge]: https://travis-ci.org/TankerHQ/identity-go.svg?branch=master
[build]: https://travis-ci.org/TankerHQ/identity-go
