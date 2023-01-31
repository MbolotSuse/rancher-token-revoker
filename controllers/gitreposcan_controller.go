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

	"github.com/mbolotsuse/rancher-token-revoker/scanner"
	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	managementv3 "github.com/mbolotsuse/rancher-token-revoker/api/v3"
	"github.com/mbolotsuse/rancher-token-revoker/revoker"
)

// GitRepoScanReconciler reconciles a GitRepoScan object
type GitRepoScanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// DefaultScanInterval is the scan interval which should be used if no scan interval is specified for a given CR
	DefaultScanInterval int
	// RevokerMode is the mode of the tokenRevoker
	RevokerMode  revoker.Mode
	scanHandlers sync.Map
}

//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=management.cattle.io,resources=gitreposcans/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the GitRepoScan object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *GitRepoScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
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

	repoScanner := scanner.GitRepoScanner{
		RepoUrl: scan.Spec.RepoUrl,
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

// scanConfig holds all of the args required to scan a single repo
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
	logrus.Infof("running scan of repo %s every %d seconds", config.scan.Name+"/"+config.scan.Namespace, duration)
	// TODO: update cr on scan with
	// time.Now().Format(time.RFC3339)
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
			logrus.Infof("scanning %s", config.scan.Namespace+"/"+config.scan.Name)
			reports, err := config.scanner.Scan()
			if err != nil {
				logrus.Errorf("unable to scan repo %s", err.Error())
				continue
			}
			logrus.Infof("found %d exposed credentials", len(reports))
			for _, report := range reports {
				logrus.Infof("Value matching rancher token pattern found in %s at commit %s by author %s ", config.scan.Spec.RepoUrl, report.Commit, report.Author)
				err := config.revoker.RevokeTokenByValue(report.Secret)
				if err != nil {
					logrus.Infof("Unable to revoke token with error %s", err.Error())
				}
			}
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitRepoScanReconciler) SetupWithManager(mgr ctrl.Manager) error {

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &rancherv3.Token{}, revoker.IndexerKey, func(rawObj client.Object) []string {
		token := rawObj.(*rancherv3.Token)
		return []string{token.Token}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&managementv3.GitRepoScan{}).
		Complete(r)
}
