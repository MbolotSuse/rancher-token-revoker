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

// GithubOrgScanConfig holds scan options specific to a github org
type GithubOrgScanConfig struct {
	// BaseUrl is the baseURl used for api calls to github. If empty, uses the default url for the public github instance
	BaseUrl string `json:"baseUrl,omitempty"`
	// UploadUrl is the uploadURl used for api calls to github. If empty, uses the default url for the public github instance
	UploadUrl string `json:"uploadUrl,omitempty"`
	// SecretName is the name of the secret that will be used to query the API for org information. Required value.
	// Secret.Type must be management.cattle.io/github-token, which has one key "accessToken" and one value (the access token)
	SecretName string `json:"secretName"`
}

// OrgScanConfig holds options related to how the org's information (such as list of repos) is refreshed, and how often
type OrgScanConfig struct {
	// OrgScanInterval is the time between the last scan's start time and the next time a scan will be run.
	OrgScanInterval int `json:"orgScanInterval,omitempty"`
	// RepoUrlType is the type of url which should be used for each url in the repo. Valid values are https, ssh
	RepoUrlType string `json:"repoUrlType,omitempty"`
	// GithubOrgScanConfig is the config containing github-specific options.
	GithubOrgScanConfig *GithubOrgScanConfig `json:"githubOrgScanConfig"`
}

// GitOrgScanSpec defines the desired state of GitOrgScan
type GitOrgScanSpec struct {
	// FullOrgName is the name of the org, in the full path, as known by the git provider
	FullOrgName string `json:"fullOrgName"`
	// OrgScanConfig contains options to determine when/how to refresh org information
	OrgScanConfig OrgScanConfig `json:"orgScanConfig"`
	// RepoScanConfig is the ScanConfig to be used for every repo in this org
	RepoScanConfig RepoScanConfig `json:"repoScanConfig"`
}

// GitOrgScanStatus defines the observed state of GitOrgScan
type GitOrgScanStatus struct {
	// Deployed indicates if the scans for the sub-resources of this org have been successfully rolled out
	Deployed bool `json:"deployed"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// GitOrgScan is the Schema for the gitorgscans API
type GitOrgScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GitOrgScanSpec   `json:"spec,omitempty"`
	Status GitOrgScanStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// GitOrgScanList contains a list of GitOrgScan
type GitOrgScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GitOrgScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitOrgScan{}, &GitOrgScanList{})
}
