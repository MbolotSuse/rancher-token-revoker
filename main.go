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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mbolotsuse/rancher-token-revoker/revoker"
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	managementv3 "github.com/mbolotsuse/rancher-token-revoker/api/v3"
	"github.com/mbolotsuse/rancher-token-revoker/controllers"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const defaultNamespace = "cattle-revoker-system"

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(managementv3.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var defaultScanIntervalSeconds int
	var revokeMode string
	var defaultSecret string
	var debug bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&defaultScanIntervalSeconds, "default-scan-interval", 60, "Default scan interval in seconds")
	flag.StringVar(&revokeMode, "revoke-mode", "disable", "Action to take on discovering exposed tokens. Allowed values are warn, disable, delete")
	flag.StringVar(&defaultSecret, "default-secret", "", "Optional: default secret (in $K8S_NAMESPACE) which contains authentication value to be used by default for repo access")
	flag.BoolVar(&debug, "debug", false, "Debug mode - default false")
	opts := zap.Options{
		Development: debug,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	revokerMode, err := convertRevokerArgToRevokerMode(revokeMode)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	namespace, ok := os.LookupEnv("K8S_NAMESPACE")
	if !ok {
		namespace = defaultNamespace
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "fb99b70e.cattle.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.GitRepoScanReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		DefaultScanInterval: defaultScanIntervalSeconds,
		RevokerMode:         revokerMode,
		Namespace:           namespace,
		DefaultAuthSecret:   defaultSecret,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "GitRepoScan")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func convertRevokerArgToRevokerMode(revokerArg string) (revoker.Mode, error) {
	switch revokerArg {
	case "warn":
		return revoker.ModeWarn, nil
	case "disable":
		return revoker.ModeDisable, nil
	case "delete":
		return revoker.ModeDelete, nil
	default:
		return -1, fmt.Errorf("unrecognized revoker mode %s, see help for allowed args", revokerArg)
	}
}
