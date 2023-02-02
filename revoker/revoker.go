package revoker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Mode int

const (
	ModeWarn Mode = iota
	ModeDisable
	ModeDelete

	// IndexerKey is the key that our indexer will use to store the value of the token for easy lookup
	IndexerKey = ".key.value"
	// The rancher-provided version for SHA hashes
	shaVersion = 2
)

// tokenHashingKey is the identifier for the token-hashing feature
var tokenHashingKey = client.ObjectKey{
	// features are not namespaced
	Namespace: "",
	Name:      "token-hashing",
}

// TokenRevoker handles the actual revoking of exposed tokens
type TokenRevoker struct {
	// Client is the client to be used to lookup/disable/delete tokens
	Client client.Client
	// Mode is the mode the Revoker operates in
	Mode Mode
}

// RevokeTokenByValue finds tokens which have the input value and revokes them (based on mode).
// Only works if token-hashing is disabled
func (t *TokenRevoker) RevokeTokenByValue(tokenValue string, exceptedTokenNames map[string]struct{}) error {
	err := t.revokeTokenByIndexer(tokenValue, exceptedTokenNames)
	if err != nil {
		tokenHashingEnabled, err := t.tokenHashingEnabled()
		if err != nil {
			return fmt.Errorf("unable to determine if token hashing is enabled %w", err)
		}
		// given how expensive this is, only do it if we are sure that we need to
		if tokenHashingEnabled {
			return t.revokeTokenFromHashedTokens(tokenValue, exceptedTokenNames)
		}
	}
	return nil
}

// revokeTokenByIndexer revokes tokens using the by-value indexer. Unfortunately, this quicker method is only available
// when token hashing is disabled, since we hash tokens using a salt
func (t *TokenRevoker) revokeTokenByIndexer(tokenValue string, exceptedTokenNames map[string]struct{}) error {
	var tokenList rancherv3.TokenList
	err := t.Client.List(context.Background(), &tokenList, client.MatchingFields{IndexerKey: tokenValue})
	if err != nil {
		return err
	}
	if len(tokenList.Items) == 0 {
		return fmt.Errorf("unable to find token by value for token value, token will not be revoked")
	}
	if len(tokenList.Items) > 1 {
		logrus.Warnf("more than one token found for a value, unexpected behavior may occur")
	}
	errors := errorList{}
	for _, token := range tokenList.Items {
		err = t.revoke(token, exceptedTokenNames)
		if err != nil {
			errors.append(err)
		}
	}
	if !errors.IsNil() {
		return &errors
	}
	return nil
}

// revokeTokenFromHashedTokens revokes a token by value given that all tokens are hashed. Since our hashes use salts, we
// can't pre-compute the target hash and need to check every token. This is very inefficient.
func (t *TokenRevoker) revokeTokenFromHashedTokens(tokenValue string, exceptedTokenNames map[string]struct{}) error {
	var tokenList rancherv3.TokenList
	err := t.Client.List(context.Background(), &tokenList)
	if err != nil {
		return err
	}
	ctx := context.Background()
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	type calcResult struct {
		tokenName string
		matches   bool
	}
	// don't spin up more go-routines than we can take advantage of
	results := make(chan calcResult)
	maxWorkers := runtime.GOMAXPROCS(0)
	sem := semaphore.NewWeighted(int64(maxWorkers))
	// launch the worker threads, async so that we don't tie up the receive happening later
	// adapted from https://pkg.go.dev/golang.org/x/sync/semaphore
	go func() {
		for _, token := range tokenList.Items {
			token := token
			if err := sem.Acquire(cancelCtx, 1); err != nil {
				// in all likelihood, this is caused by a cancel, indicating that we have found the result
				// so log this at a level of debug
				logrus.Debugf("token hashing evaluation for %s canceled", token.Name)
			}
			// launch a worker thread to validate this hash, releasing the semaphore after done
			go func() {
				//TODO: Right now this is not memoized. This can lead to large inefficiencies for setups which don't use
				// any ignore functionality
				err := VerifySHA256Hash(token.Token, tokenValue)
				if err != nil {
					results <- calcResult{
						tokenName: token.Name,
						matches:   false,
					}
				} else {
					results <- calcResult{
						tokenName: token.Name,
						matches:   true,
					}
				}
				defer sem.Release(1)
			}()
		}
	}()

	total := 0
	for {
		result := <-results
		total += 1
		if result.matches {
			cancelFunc()
			tokenKey := client.ObjectKey{
				Name: result.tokenName,
				// tokens are not namespaced
			}
			var token rancherv3.Token
			err := t.Client.Get(context.Background(), tokenKey, &token)
			if err != nil {
				return fmt.Errorf("unable to re-fetch target token for revoking %w", err)
			}
			return t.revoke(token, exceptedTokenNames)
		}
		if total == len(tokenList.Items) {
			cancelFunc()
			break
		}
	}
	return fmt.Errorf("no hashed token found for the value")
}

// revoke handles the action/backend revoking once we have identified a target token
func (t *TokenRevoker) revoke(token rancherv3.Token, exceptedTokenNames map[string]struct{}) error {
	if _, ok := exceptedTokenNames[token.Name]; ok {
		logrus.Infof("Will not revoke token %s as there is an exception for it", token.Name)
		return nil
	}
	switch t.Mode {
	// This is also the default case if no mode was set
	case ModeWarn:
		logrus.Warnf("token %s was exposed, but will not be modified since the revoker's mode is warn", token.Name)
	case ModeDisable:
		enabled := false
		token.Enabled = &enabled
		logrus.Infof("token %s was exposed, will now set token.enabled to false", token.Name)
		err := t.Client.Update(context.Background(), &token)
		if err != nil {
			return err
		}
	case ModeDelete:
		logrus.Infof("token %s was exposed, will now delete", token.Name)
		err := t.Client.Delete(context.Background(), &token)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid mode %d, no action will be taken for token %s", t.Mode, token.Name)
	}
	return nil
}

func (t *TokenRevoker) tokenHashingEnabled() (bool, error) {
	var tokenHashingFeature rancherv3.Feature
	err := t.Client.Get(context.Background(), tokenHashingKey, &tokenHashingFeature)
	if err != nil {
		return false, err
	}
	defaultValue := tokenHashingFeature.Status.Default
	isEnabled := tokenHashingFeature.Spec.Value != nil && *tokenHashingFeature.Spec.Value
	return defaultValue || isEnabled, nil

}

// VerifySHA256Hash takes a key and compares it with stored hash, including its salt
// Directly taken from https://github.com/rancher/rancher/blob/4254eda21f13b9c16ca75bbd8269578eb938d549/pkg/auth/tokens/sha256.go#L31
func VerifySHA256Hash(hash, secretKey string) error {
	if !strings.HasPrefix(hash, "$") {
		return fmt.Errorf("hash format invalid")
	}
	splitHash := strings.SplitN(strings.TrimPrefix(hash, "$"), ":", 3)
	if len(splitHash) != 3 {
		return fmt.Errorf("hash format invalid")
	}

	version, err := strconv.Atoi(splitHash[0])
	if err != nil {
		return err
	}
	if version != shaVersion {
		return fmt.Errorf("hash version %d does not match package version %d", version, shaVersion)
	}

	salt, enc := splitHash[1], splitHash[2]
	// base64 decode stored salt and key
	decodedKey, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		return err
	}
	if len(decodedKey) < 1 {
		return fmt.Errorf("secretKey hash does not match") // Don't allow accidental empty string to succeed
	}
	decodedSalt, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return err
	}
	// compare the two
	hashedSecretKey := sha256.Sum256([]byte(string(decodedSalt) + secretKey))
	if subtle.ConstantTimeCompare(decodedKey, hashedSecretKey[:]) == 0 {
		return fmt.Errorf("secretKey hash does not match")
	}
	return nil
}
