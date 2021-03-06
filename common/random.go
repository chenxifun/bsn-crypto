package common

import (
	"crypto/rand"
	"math/big"

	"github.com/pkg/errors"
)

const (
	// NonceSize is the default NonceSize
	NonceSize = 24
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	// TODO: rand could fill less bytes then len
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting random bytes")
	}

	return key, nil
}

// GetRandomNonce returns a random byte array of length NonceSize
func GetRandomNonce() ([]byte, error) {
	return GetRandomBytes(NonceSize)
}

func GetRandomBigInt() (*big.Int, error) {
	b, err := GetRandomBytes(32)

	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil

}
