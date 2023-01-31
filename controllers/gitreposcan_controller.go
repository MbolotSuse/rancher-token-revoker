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
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	managementv3 "github.com/mbolotsuse/rancher-token-revoker/api/v3"
)

// GitRepoScanReconciler reconciles a GitRepoScan object
type GitRepoScanReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
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
	go r.startRepoScans(cancelContext, repoScanner, scan)

	return ctrl.Result{}, nil
}

func (r *GitRepoScanReconciler) startRepoScans(ctx context.Context, scanner scanner.GitRepoScanner, scan managementv3.GitRepoScan) {
	duration := scan.Spec.ScanIntervalSeconds
	// TODO: This value should be read from env vars/prog args
	if duration <= 0 {
		duration = 60
	}
	ticker := time.NewTicker(time.Duration(scan.Spec.ScanIntervalSeconds) * time.Second)
	logrus.Infof("running ticker with interval %d, %d", time.Duration(scan.Spec.ScanIntervalSeconds)*time.Second, 5*time.Second)
	// TODO: update cr on scan with
	// time.Now().Format(time.RFC3339)
	for {
		select {
		case <-ctx.Done():
			logrus.Infof("shutdown signal received for %s", scan.Namespace+"/"+scan.Name)
			err := scanner.Stop()
			if err != nil {
				logrus.Errorf("unable to stop scanner %s", err.Error())
			}
			return
		case <-ticker.C:
			logrus.Infof("scanning %s", scan.Namespace+"/"+scan.Name)
			reports, err := scanner.Scan()
			if err != nil {
				logrus.Errorf("unable to scan repo %s", err.Error())
				continue
			}
			logrus.Infof("found %d exposed credentials", len(reports))
			for _, report := range reports {
				logrus.Infof("Exposed token found: %+v", report)
			}
		}
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitRepoScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&managementv3.GitRepoScan{}).
		Complete(r)
}
