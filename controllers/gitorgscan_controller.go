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

	managementv3 "github.com/mbolotsuse/rancher-token-revoker/api/v3"
	"github.com/mbolotsuse/rancher-token-revoker/org"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	githubSecretType = "management.cattle.io/github-token"
	githubSecretKey  = "accessToken"
	byOwnerIndex     = ".index.ownerName"
	repoUrlIndex     = ".index.repoUrl"
)

// GitOrgScanReconciler reconciles a GitOrgScan object
type GitOrgScanReconciler struct {
	client.Client
	// adapted from https://github.com/aws-controllers-k8s/runtime/pull/49/files
	APIReader client.Reader
	Scheme    *runtime.Scheme
	// DefaultScanInterval is the scan interval which should be used if no scan interval is specified for a given CR
	DefaultScanInterval int
	// Namespace is the namespace the revoker is running in
	Namespace    string
	scanHandlers sync.Map
}

//+kubebuilder:rbac:groups=management.cattle.io,resources=gitorgscans,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitorgscans/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitorgscans/finalizers,verbs=update

// Reconcile queries an org for a list of repos and creates/manages repo scans for each of the discovered repos
func (r *GitOrgScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// if we have a running handler, stop it so that we can restart it with the update configuration
	if value, ok := r.scanHandlers.Load(req.NamespacedName); ok {
		logrus.Infof("Stopping watch for %s", req.NamespacedName)
		cancelFunc := value.(context.CancelFunc)
		cancelFunc()
	}

	var orgScan managementv3.GitOrgScan
	err := r.Get(ctx, req.NamespacedName, &orgScan)
	if err != nil {
		// if we can't get the scan, it's possible that we enqueued too early or that this was for a deletion event
		// either way, move on and don't re-enqueue
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// creating/storing a cancel func allows us to cancel this later on so we can start/stop on resource change/delete
	cancelContext, cancelFunc := context.WithCancel(ctx)
	r.scanHandlers.Store(req.NamespacedName, cancelFunc)
	var orgScanner org.GithubOrgScanner
	if orgScan.Spec.OrgScanConfig.GithubOrgScanConfig != nil {
		accessToken, err := r.getGithubAuthToken(orgScan.Spec.OrgScanConfig.GithubOrgScanConfig.SecretName)
		if err != nil {
			logrus.Errorf("unable to get access token %s", err.Error())
		}
		baseUrl := orgScan.Spec.OrgScanConfig.GithubOrgScanConfig.BaseUrl
		uploadUrl := orgScan.Spec.OrgScanConfig.GithubOrgScanConfig.UploadUrl
		if baseUrl == "" {
			baseUrl = org.DefaultBaseURL
		}
		if uploadUrl == "" {
			uploadUrl = org.DefaultUploadURL
		}
		scanner, err := org.NewGithubOrgScanner(baseUrl, uploadUrl, accessToken)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to init org")
		}
		orgScanner = *scanner
	}
	go r.startOrgScans(cancelContext, orgScan, &orgScanner)

	return ctrl.Result{}, nil
}

func (r *GitOrgScanReconciler) startOrgScans(ctx context.Context, orgScan managementv3.GitOrgScan, orgScanner *org.GithubOrgScanner) {
	duration := orgScan.Spec.OrgScanConfig.OrgScanInterval
	if duration <= 0 {
		duration = r.DefaultScanInterval
	}
	tickInterval := time.Duration(duration) * time.Second
	ticker := time.NewTicker(tickInterval)
	logrus.Infof("running scan of org %s every %d seconds", orgScan.Spec.FullOrgName, duration)
	for {
		select {
		case <-ctx.Done():
			logrus.Infof("shutdown signal received for %s/%s", orgScan.Name, orgScan.Namespace)
			return
		case <-ticker.C:
			repoType, err := convertRepoType(orgScan.Spec.OrgScanConfig.RepoUrlType)
			if err != nil {
				logrus.Errorf("unable to get repo type: %s", err.Error())
				continue
			}
			repoUrls, err := orgScanner.ListRepoURLs(orgScan.Spec.FullOrgName, repoType)
			if err != nil {
				logrus.Errorf("unable to determine repo urls for org %s: %s", orgScan.Spec.FullOrgName, err)
			}
			for _, url := range repoUrls {
				var currentScans managementv3.GitRepoScanList
				// use an indexer to get only the scans that we own and are for this url
				err := r.List(ctx, &currentScans, client.MatchingFields{byOwnerIndex: orgScan.Name}, client.MatchingFields{repoUrlIndex: url}, client.InNamespace(orgScan.Namespace))
				if err != nil {
					logrus.Errorf("unable to list repo scans %s", err.Error())
					continue
				}
				if len(currentScans.Items) == 0 {
					err := r.createRepoScan(url, orgScan)
					if err != nil {
						logrus.Errorf("unable to create repo scan %s", err.Error())
					}
					continue
				} else if len(currentScans.Items) > 1 {
					logrus.Infof("found more than one repo scan for a url owned by %s, will only update the first", orgScan.Name)
				}
				currentScan := currentScans.Items[0]
				if currentScan.Spec.Config != orgScan.Spec.RepoScanConfig {
					currentScan.Spec.Config = orgScan.Spec.RepoScanConfig
					err := r.Update(context.Background(), &currentScan)
					if err != nil {
						logrus.Errorf("unable to update scan config %s/%s: %s", currentScan.Name, currentScan.Namespace, err.Error())
					}
				}
			}
		}
	}
}

func (r *GitOrgScanReconciler) createRepoScan(url string, orgScan managementv3.GitOrgScan) error {
	gitRepoScan := managementv3.GitRepoScan{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    orgScan.Namespace,
			GenerateName: "reposcan-",
		},
		Spec: managementv3.GitRepoScanSpec{
			RepoUrl: url,
			Config:  orgScan.Spec.RepoScanConfig,
		},
	}
	err := ctrl.SetControllerReference(&orgScan, &gitRepoScan, r.Scheme)
	if err != nil {
		return fmt.Errorf("unable to set controller ref %w", err)
	}
	return r.Create(context.Background(), &gitRepoScan)
}

func (r *GitOrgScanReconciler) getGithubAuthToken(secretName string) (string, error) {
	secretKey := client.ObjectKey{
		Name:      secretName,
		Namespace: r.Namespace,
	}
	var secret v1.Secret
	err := r.APIReader.Get(context.Background(), secretKey, &secret)
	if err != nil {
		return "", fmt.Errorf("unbale to get github auth token: %w", err)
	}
	if secret.Type != githubSecretType {
		return "", fmt.Errorf("specified secret did not have the correct type")
	}
	bytesToken, ok := secret.Data[githubSecretKey]
	if !ok {
		return "", fmt.Errorf("secret was missing a key/value pair for the %s key", githubSecretKey)
	}
	return string(bytesToken), nil
}

func convertRepoType(repoType string) (org.RepoType, error) {
	switch repoType {
	case "https":
		return org.RepoTypeHTTP, nil
	case "ssh":
		return org.RepoTypeSSH, nil
	default:
		return 0, fmt.Errorf("unrecognized repo type %s", repoType)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitOrgScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &managementv3.GitRepoScan{}, byOwnerIndex, func(rawObj client.Object) []string {
		// adapted from https://github.com/kubernetes-sigs/kubebuilder/blob/fc673e4d21491072df358636f9623cd48edce8e1/docs/book/src/cronjob-tutorial/testdata/project/controllers/cronjob_controller.go#L558
		repoScan := rawObj.(*managementv3.GitRepoScan)
		owner := metav1.GetControllerOf(repoScan)
		if owner == nil {
			return nil
		}
		if owner.APIVersion != managementv3.GroupVersion.String() || owner.Kind != "GitOrgScan" {
			return nil
		}
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &managementv3.GitRepoScan{}, repoUrlIndex, func(rawObj client.Object) []string {
		// adapted from https://github.com/kubernetes-sigs/kubebuilder/blob/fc673e4d21491072df358636f9623cd48edce8e1/docs/book/src/cronjob-tutorial/testdata/project/controllers/cronjob_controller.go#L558
		repoScan := rawObj.(*managementv3.GitRepoScan)
		return []string{repoScan.Spec.RepoUrl}
	}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&managementv3.GitOrgScan{}).
		Complete(r)
}
