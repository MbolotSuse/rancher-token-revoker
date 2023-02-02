/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	managementv3 "github.com/mbolotsuse/rancher-token-revoker/api/v3"
	"github.com/mbolotsuse/rancher-token-revoker/revoker"
	"github.com/mbolotsuse/rancher-token-revoker/scanner"
	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// gitSSHUser defines the user to attempt to auth as when cloning a private repo. For github/gitlab this appears to be
	// git. Might be good to make this customizable in the future
	gitSSHUser = "git"
	// exceptionIndexerKey is the key used to index scan exceptions
	exceptionIndexerKey = ".byValue"
	// byName is the value used for the exception indexer when the exception is based on tokenName
	byName = "name"
	// byValue is the value used for the exception indexer when the exception is based on tokenValue
	byValue = "value"
)

// GitRepoScanReconciler reconciles a GitRepoScan object
type GitRepoScanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// DefaultScanInterval is the scan interval which should be used if no scan interval is specified for a given CR
	DefaultScanInterval int
	// DefaultAuthSecret is the secret used to pull from private repos if no cred is specified for that repo
	DefaultAuthSecret string
	// RevokerMode is the mode of the tokenRevoker
	RevokerMode revoker.Mode
	// Namespace is the namespace that the controller is running in
	Namespace    string
	scanHandlers sync.Map
}

//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans/finalizers,verbs=update

// Reconcile attempts to launch a go-routine processing a scan of a repo. If an existing repo scan is already running
// it cancels the current scan before launching a new one (to ensure that the new settings take effect)
func (r *GitRepoScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// if we have a running handler, stop it so that we can restart it with the update configuration
	if value, ok := r.scanHandlers.Load(req.NamespacedName); ok {
		logrus.Infof("Stopping watch for %s", req.NamespacedName)
		cancelFunc := value.(context.CancelFunc)
		cancelFunc()
	}

	var scan managementv3.GitRepoScan
	err := r.Get(ctx, req.NamespacedName, &scan)
	if err != nil {
		// if we can't get the scan, it's possible that we enqueued too early or that this was for a deletion event
		// either way, move on and don't re-enqueue
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// creating/storing a cancel func allows us to cancel this later on so we can start/stop on resource change/delete
	cancelContext, cancelFunc := context.WithCancel(ctx)
	r.scanHandlers.Store(req.NamespacedName, cancelFunc)

	var gitAuthSecret string
	isDefault := false
	// use the value specified for this repo, or fallback to the default provided for the controller
	if scan.Spec.ForceNoAuth {
		gitAuthSecret = ""
	} else if scan.Spec.RepoSecretName != "" {
		gitAuthSecret = scan.Spec.RepoSecretName
	} else if r.DefaultAuthSecret != "" {
		gitAuthSecret = r.DefaultAuthSecret
		isDefault = true
	}

	var repoScanner scanner.GitRepoScanner
	if gitAuthSecret != "" {
		authMethod, err := r.readAuthMethodFromSecret(gitAuthSecret)
		if err != nil {
			errorMessage := fmt.Sprintf("unable to create auth method from secret: %s", err)
			if isDefault {
				errorMessage = fmt.Sprintf("unable to create auth method from default application secret")
				logrus.Errorf("unable to create auth method from default secret: %s", err.Error())
			}
			// The user may/may not be able to see the controller logs, but they will be able to see the status on their
			// repo scan, so update the scan object accordingly
			_, updErr := r.updateScanStatus(scan, false, errorMessage)
			if updErr != nil {
				logrus.Errorf("unable to update scan status, %s", updErr)
			}
			return ctrl.Result{Requeue: false}, fmt.Errorf("unable to read auth method from secret: %w", err)
		}
		repoScanner = scanner.GitRepoScanner{
			RepoUrl:    scan.Spec.RepoUrl,
			AuthMethod: authMethod,
		}
	} else {
		repoScanner = scanner.GitRepoScanner{
			RepoUrl: scan.Spec.RepoUrl,
		}
	}

	err = repoScanner.Start()
	if err != nil {
		logrus.Infof("%t", err == nil)
		return ctrl.Result{}, fmt.Errorf("unable to initialize scan %w", err)
	}
	tokenRevoker := revoker.TokenRevoker{
		Mode:   r.RevokerMode,
		Client: r.Client,
	}
	go r.startRepoScans(cancelContext, scanConfig{
		scan:    scan,
		scanner: repoScanner,
		revoker: tokenRevoker,
	})

	return ctrl.Result{}, nil
}

// scanConfig holds the args required to scan a single repo
type scanConfig struct {
	scan    managementv3.GitRepoScan
	scanner scanner.GitRepoScanner
	revoker revoker.TokenRevoker
}

func (r *GitRepoScanReconciler) startRepoScans(ctx context.Context, config scanConfig) {
	duration := config.scan.Spec.ScanIntervalSeconds
	if duration <= 0 {
		duration = r.DefaultScanInterval
	}
	tickInterval := time.Duration(duration) * time.Second
	ticker := time.NewTicker(tickInterval)
	logrus.Infof("running scan of repo %s every %d seconds", config.scan.Spec.RepoUrl, duration)
	for {
		select {
		case <-ctx.Done():
			logrus.Infof("shutdown signal received for %s", config.scan.Namespace+"/"+config.scan.Name)
			err := config.scanner.Stop()
			if err != nil {
				logrus.Errorf("unable to stop scanner %s", err.Error())
			}
			return
		case <-ticker.C:
			valueExceptions, nameExceptions, err := r.getExceptionSets()
			if err != nil {
				// zero these out in case some invalid data is returned
				valueExceptions = map[string]struct{}{}
				nameExceptions = map[string]struct{}{}
				logrus.Errorf("unable to get name/value exceptions, some exceptions may be ignored: %s", err.Error())
			}
			logrus.Infof("scanning %s", config.scan.Namespace+"/"+config.scan.Name)
			reports, err := config.scanner.Scan()
			if err != nil {
				logrus.Errorf("unable to scan repo %s", err.Error())
				newScan, updErr := r.updateScanStatus(config.scan, false, err.Error())
				if updErr != nil {
					logrus.Errorf("unable to update scan status %s", updErr.Error())
					continue
				}
				config.scan = *newScan
				continue
			}
			newScan, updErr := r.updateScanStatus(config.scan, true, "")
			if updErr != nil {
				logrus.Errorf("unable to update scan status %s", updErr.Error())
			} else {
				config.scan = *newScan
			}
			logrus.Infof("found %d exposed credentials", len(reports))
			for _, report := range reports {
				if _, ok := valueExceptions[report.Secret]; ok {
					logrus.Infof("Exception found for token in %s at commit %s, skipping with no action taken", config.scan.Spec.RepoUrl, report.Commit)
					continue
				}
				logrus.Infof("Value matching rancher token pattern found in %s at commit %s by author %s ", config.scan.Spec.RepoUrl, report.Commit, report.Author)
				err := config.revoker.RevokeTokenByValue(report.Secret, nameExceptions)
				if err != nil {
					logrus.Infof("Unable to revoke token with error %s", err.Error())
				}
			}
		}
	}
}

// readAuthMethodFromSecret fetches the specified secret in the controller's namespace and converts to the applicable AuthMethod
func (r *GitRepoScanReconciler) readAuthMethodFromSecret(secretName string) (transport.AuthMethod, error) {
	secretKey := client.ObjectKey{
		Name:      secretName,
		Namespace: r.Namespace,
	}
	var secret v1.Secret
	err := r.Client.Get(context.Background(), secretKey, &secret)
	if err != nil {
		return nil, fmt.Errorf("unable to get scret: %w", err)
	}
	switch secret.Type {
	case v1.SecretTypeBasicAuth:
		bytesUsername, ok := secret.Data[v1.BasicAuthUsernameKey]
		// k8s should be validating these fields, but double-check it just in case
		if !ok {
			return nil, fmt.Errorf("secret was of type %s, but there was no %s key", v1.SecretTypeBasicAuth, v1.BasicAuthUsernameKey)
		}
		bytesPassword, ok := secret.Data[v1.BasicAuthPasswordKey]
		if !ok {
			return nil, fmt.Errorf("secret was of type %s, bu there was no %s key", v1.SecretTypeBasicAuth, v1.BasicAuthPasswordKey)
		}
		return &http.BasicAuth{Username: string(bytesUsername), Password: string(bytesPassword)}, nil
	case v1.SecretTypeSSHAuth:
		privateKey, ok := secret.Data[v1.SSHAuthPrivateKey]
		if !ok {
			return nil, fmt.Errorf("secret was of type %s, bu there was no %s key", v1.SecretTypeSSHAuth, v1.SSHAuthPrivateKey)
		}
		// password should be empty. This value is not expected to be encrypted with a passphrase, since any passphrase
		// would have to be fed to the application through a secret.
		return ssh.NewPublicKeys(gitSSHUser, privateKey, "")
	default:
		return nil, fmt.Errorf("unrecognized secret type %s, ensure that the secret type is one of the approved types", secret.Type)
	}
}

// updateScanStatus updates the status of a scan. Success should be false if we failed. Message should only be non-empty
// if we failed
func (r *GitRepoScanReconciler) updateScanStatus(scan managementv3.GitRepoScan, success bool, message string) (*managementv3.GitRepoScan, error) {
	scanTime := time.Now().Format(time.RFC3339)
	scan.Status.LastScanTime = scanTime
	if !success {
		scan.Status.ScanError = &managementv3.RepoScanError{
			ErrorMessage: message,
		}
	}
	err := r.Update(context.Background(), &scan)
	return &scan, err
}

// getExceptionSets produces two sets of exceptions - the first is the values that are excepted, the second is the names that are excepted
func (r *GitRepoScanReconciler) getExceptionSets() (map[string]struct{}, map[string]struct{}, error) {
	var exceptionsByName managementv3.ScanExceptionList
	var exceptionsByValue managementv3.ScanExceptionList
	err := r.Client.List(context.Background(), &exceptionsByValue, client.MatchingFields{exceptionIndexerKey: byValue})
	if err != nil {
		return nil, nil, err
	}
	err = r.Client.List(context.Background(), &exceptionsByName, client.MatchingFields{exceptionIndexerKey: byName})
	if err != nil {
		return nil, nil, err
	}
	nameExceptions := map[string]struct{}{}
	for _, exception := range exceptionsByName.Items {
		nameExceptions[exception.Spec.TokenName] = struct{}{}
	}
	valueExceptions := map[string]struct{}{}
	for _, exception := range exceptionsByValue.Items {
		valueExceptions[exception.Spec.TokenValue] = struct{}{}
	}
	return valueExceptions, nameExceptions, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitRepoScanReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// indexer for revoker to allow for quick lookups on value -> name mapping
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &rancherv3.Token{}, revoker.IndexerKey, func(rawObj client.Object) []string {
		token := rawObj.(*rancherv3.Token)
		return []string{token.Token}
	}); err != nil {
		return err
	}
	// indexer to partition the exceptions into two lists - one for name and one for value
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &managementv3.ScanException{}, exceptionIndexerKey, func(rawObj client.Object) []string {
		exception := rawObj.(*managementv3.ScanException)
		if exception.Spec.TokenValue != "" {
			return []string{byValue}
		} else if exception.Spec.TokenName != "" {
			return []string{byName}
		}
		return []string{"invalid"}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&managementv3.GitRepoScan{}).
		Complete(r)
}
