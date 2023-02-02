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

// ScanExceptionSpec defines the desired state of ScanException
type ScanExceptionSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// TokenName is the name of the token being excepted from the scan/revoke process. It's recommended that you use TokenValue
	// for performance reasons. If both values are set, TokenValue will be used
	TokenName string `json:"tokenName,omitempty"`

	// TokenValue is the value (token.Token) of the token being excepted from the scan/revoke process.
	TokenValue string `json:"tokenValue,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster

// ScanException is the Schema for the scanexceptions API
type ScanException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ScanExceptionSpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

// ScanExceptionList contains a list of ScanException
type ScanExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScanException `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScanException{}, &ScanExceptionList{})
}
