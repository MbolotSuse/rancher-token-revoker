package revoker

import (
	"context"
	"fmt"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Mode int

const (
	ModeWarn Mode = iota
	ModeDisable
	ModeDelete

	// IndexerKey is the key that our indexer will use to store the value of the token for easy lookup
	IndexerKey = ".key.value"
)

// TokenRevoker handles the actual revoking of exposed tokens
type TokenRevoker struct {
	// Client is the client to be used to lookup/disable/delete tokens
	Client client.Client
	// Mode is the mode the Revoker operates in
	Mode Mode
}

// RevokeTokenByValue finds tokens which have the input value and revokes them (based on mode). TODO: Support Hashed tokens
func (t *TokenRevoker) RevokeTokenByValue(tokenValue string) error {
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
		err = t.revoke(token)
		if err != nil {
			errors.append(err)
		}
	}
	if !errors.IsNil() {
		return &errors
	}
	return nil
}

// revoke handles the action/backend revoking once we have identified a target token
func (t *TokenRevoker) revoke(token rancherv3.Token) error {
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
