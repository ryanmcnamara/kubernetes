/*
Copyright 2017 The Kubernetes Authors.

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

package delegatedadmission

import (
"fmt"

"k8s.io/kubernetes/pkg/api"
metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
"k8s.io/kubernetes/pkg/apis/apps"
"k8s.io/kubernetes/pkg/apis/batch"
"k8s.io/kubernetes/pkg/apis/extensions"
)

// Operation is the type of resource operation being checked for admission control
type Operation string

// Operation constants
const (
	Create  Operation = "CREATE"
	Update  Operation = "UPDATE"
	Delete  Operation = "DELETE"
	Connect Operation = "CONNECT"
)

// ExtraValue masks the value so protobuf can generate
// +protobuf.nullable=true
// +protobuf.options.(gogoproto.goproto_stringer)=false
type ExtraValue []string

func (t ExtraValue) String() string {
	return fmt.Sprintf("%v", []string(t))
}

type AdmissionReviewStatus struct {
	// Allowed is required. True if the resource should be admitted, false otherwise.
	Allowed bool
	// Mutated is optional. It indicates if the resource was mutated by the webhook. Defaults to false, if not provided.
	Mutated bool
	// Reason is optional. It indicates why a request was allowed or denied.
	Reason string
	// EvaluationError is an indication that some error occurred during the admission check.
	// it is entirely possible to get an error and be able to continue to determine admission status in spite of it.
	EvaluationError string
}

// AdmissionReviewSpec is the description of the pod admission review. It includes the user making
// the request for the pod and the pod spec itself
type AdmissionReviewSpec struct {
	// User is the user you're testing for.
	// If you specify "User" but not "Group", then is it interpreted as "What if User were not a member of any groups
	User string
	// Groups is the groups you're testing for.
	Groups []string
	// Extra corresponds to the user.Info.GetExtra() method from the authenticator.  Since that is input to the authorizer
	// it needs a reflection here.
	Extra map[string]ExtraValue

	// Operation is the operation being performed
	Operation Operation

	// Namespace is the namespace the request went to. This is required to know to what namespace to check in authorization
	// if the object does not specify it in the metadata
	Namespace string

	// Name is the name of the resource
	Name string

	// Kind specifies the type of object in the AdmissionReviewObject
	Kind string

	// Object holds the new object being reviewed for admission. May be empty if delete operation
	Object *AdmissionReviewObject
	// OldObject holds the previous version of the object being reviewed for admission. May be empty if create operation
	OldObject *AdmissionReviewObject
}

// AdmissionReviewObject represents the runtime object being reviewed for admission.
// Only one of its members may be specified.
type AdmissionReviewObject struct {
	// +optional
	Namespace *api.Namespace
	// +optional
	Pod *api.Pod
	// +optional
	Job *batch.Job
	// +optional
	ReplicationController *api.ReplicationController
	// +optional
	ReplicaSet *extensions.ReplicaSet
	// +optional
	Deployment *extensions.Deployment
	// +optional
	StatefulSet *apps.StatefulSet
	// +optional
	DaemonSet *extensions.DaemonSet
	// +optional
	Service *api.Service
	// +optional
	Ingress *extensions.Ingress
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noVerbs
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdmissionReview provides a struct to determine status and the type of admission review being requested
type AdmissionReview struct {
	metav1.TypeMeta
	api.ObjectMeta

	// Spec holds information about the review being evaluated
	Spec AdmissionReviewSpec

	// Status is filled in by the server and indicates whether the request is allowed or not
	Status AdmissionReviewStatus
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noVerbs
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdmissionReviewList is a collection of jobs.
type AdmissionReviewList struct {
	metav1.TypeMeta
	// Standard list metadata
	// More info: http://releases.k8s.io/HEAD/docs/devel/api-conventions.md#metadata
	// +optional
	metav1.ListMeta

	// Items is the list of Job.
	Items []AdmissionReview
}
