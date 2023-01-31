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

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Important: Run "make" to regenerate code after modifying this file
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RepoScanError defines
type RepoScanError struct {
	ErrorType    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// GitRepoScanSpec defines the desired state of GitRepoScan
type GitRepoScanSpec struct {

	// RepoUrl defines the target git repo to scan. Can be in https format (https://github.com/MbolotSuse/rancher-token-revoker.git)
	// or in ssh format (git@github.com:MbolotSuse/rancher-token-revoker.git)
	RepoUrl string `json:"repoUrl"`

	// RepoSecretName is the name of the secret (in the same namespace as the chart is installed in) containing the secret
	// to access the repo at RepoUrl. If empty, uses the secret configured when installing the controller
	// TODO: Update this with information on variable which controls the controller default
	RepoSecretName string `json:"repoSecretName,omitempty"`

	// ScanIntervalSeconds is time between the last scan's start time and the next time a scan will be run. If empty/0,
	// uses the default which is set on the controller.
	// TODO: Update this with information on variable which controls the controller default
	ScanIntervalSeconds int `json:"scanIntervalSeconds,omitempty"`
}

// GitRepoScanStatus defines the observed state of GitRepoScan
type GitRepoScanStatus struct {
	// LastScanTime records the last time a scan was completed in RFC3339 format. If "", no scans have been attempted
	LastScanTime string `json:"lastScanTime,omitempty"`

	// ScanError records the error from the last scan. If nil, the last scan succeeded
	ScanError *RepoScanError `json:"scanError,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// GitRepoScan is the Schema for the gitreposcans API
type GitRepoScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GitRepoScanSpec   `json:"spec,omitempty"`
	Status GitRepoScanStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// GitRepoScanList contains a list of GitRepoScan
type GitRepoScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitRepoScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitRepoScan{}, &GitRepoScanList{})
}
