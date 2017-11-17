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
package webhook_palantir

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"text/template"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/api/delegatedadmission/v1alpha1"
	"k8s.io/kubernetes/pkg/apis/extensions"
	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

const (
	defaultConfigTmplYAML = `webhook:
  kubeConfigFile: "{{ .KubeConfig }}"
  retryBackoff: "{{ .RetryBackoff }}"
  whitelistImages:  {{ .WhitelistImages }}
`
	whitelistImage = "scratch"

	testAnnotationKey   = "test"
	testAnnotationValue = "value"
)

type Service interface {
	Review(v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error)
}

// newAdmissionWebhook creates a temporary kubeconfig file from the provided arguments and attempts to load
// a new WebhookAdmissionController from it.
func newAdmissionWebhook(callbackURL string, clientCert, clientKey, ca []byte) (*WebhookAdmissionController, error) {
	tempfile, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	p := tempfile.Name()
	defer os.Remove(p)
	config := clientcmdv1.Config{
		Clusters: []clientcmdv1.NamedCluster{
			{
				Cluster: clientcmdv1.Cluster{Server: callbackURL, CertificateAuthorityData: ca},
			},
		},
		AuthInfos: []clientcmdv1.NamedAuthInfo{
			{
				AuthInfo: clientcmdv1.AuthInfo{ClientCertificateData: clientCert, ClientKeyData: clientKey},
			},
		},
	}
	if err := json.NewEncoder(tempfile).Encode(config); err != nil {
		return nil, err
	}

	tempconfigfile, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	pc := tempconfigfile.Name()
	defer os.Remove(pc)

	configTmpl, err := template.New("testconfig").Parse(defaultConfigTmplYAML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse test template: %v", err)
	}

	whitelistStr, err := json.Marshal([]string{whitelistImage})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal whitelist image array to json: %v", err)
	}

	dataConfig := struct {
		KubeConfig      string
		RetryBackoff    string
		WhitelistImages string
	}{
		KubeConfig:      p,
		RetryBackoff:    "0s",
		WhitelistImages: string(whitelistStr),
	}
	if err := configTmpl.Execute(tempconfigfile, dataConfig); err != nil {
		return nil, fmt.Errorf("failed to execute test template: %v", err)
	}

	// Create a new admission controller
	configFile, err := os.Open(pc)
	if err != nil {
		return nil, fmt.Errorf("failed to read test config: %v", err)
	}
	defer configFile.Close()
	wh, err := New(configFile)
	return wh, err
}

func NewTestServer(s Service, cert, key, caCert []byte) (*httptest.Server, error) {
	var tlsConfig *tls.Config
	if cert != nil {
		cert, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	if caCert != nil {
		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCert)
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.ClientCAs = rootCAs
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	serveHTTP := func(w http.ResponseWriter, r *http.Request) {
		var review v1alpha1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode body: %v", err), http.StatusBadRequest)
			return
		}
		resp, err := s.Review(review)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to review admission request: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(serveHTTP))
	server.TLS = tlsConfig
	server.StartTLS()
	return server, nil
}

type mutateFn func(v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error)

type assertionFn func(attributes admission.Attributes, t *testing.T)

type mockService struct {
	allow     bool
	mutations []mutateFn
}

func (m *mockService) Review(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	ar.Status.Allowed = m.allow

	if len(m.mutations) > 0 {
		ar.Status.Mutated = true
	}

	if ar.Spec.Namespace == "" && ar.Namespace == "" {
		return ar, errors.New("Must specify namespace in either object or request")
	}

	for _, mutation := range m.mutations {
		mutated, err := mutation(ar)
		if err != nil {
			ar.Status.EvaluationError = err.Error()
			ar.Status.Allowed = false
			return ar, err
		}
		ar = mutated
	}

	return ar, nil
}

func TestWebookNamespaceInclusion(t *testing.T) {
	svc := &mockService{allow: true}
	s, err := NewTestServer(svc, serverCert, serverKey, caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		attr        admission.Attributes
		err         bool
	}{
		{
			attr: admission.NewAttributesRecord(&noNamespacePodSpec, nil, api.Kind("Pod").WithVersion("version"), "namespace",
				"", api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&noNamespacePodSpec, nil, api.Kind("Pod").WithVersion("version"), "",
				"", api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			err:         true,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceDeploymentSpec, nil, api.Kind("Deployment").WithVersion("version"),
				"TestNamespace", "TestDeployment", api.Resource("deployments").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceDeploymentSpec, nil, api.Kind("Deployment").WithVersion("version"),
				"", "TestDeployment", api.Resource("deployments").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         true,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceServiceSpec, nil, api.Kind("Service").WithVersion("version"),
				"TestNamespace", "TestService", api.Resource("services").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceServiceSpec, nil, api.Kind("Service").WithVersion("version"),
				"", "TestService", api.Resource("services").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         true,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceIngressSpec, nil, api.Kind("Ingress").WithVersion("version"),
				"TestNamespace", "TestIngress", api.Resource("ingress").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&noNamespaceIngressSpec, nil, api.Kind("Ingress").WithVersion("version"),
				"", "TestIngress", api.Resource("ingress").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			err:         true,
		},
	}
	wh, err := newAdmissionWebhook(s.URL, clientCert, clientKey, caCert)
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		err = wh.Admit(test.attr)
		if test.err {
			if err == nil {
				t.Errorf("Expected test %d to return error but none was returned", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("expected test %d to not return error but an error was found: %v", i, err)
			continue
		}
	}
}

func TestWebhookMutate(t *testing.T) {
	svc := new(mockService)
	s, err := NewTestServer(svc, serverCert, serverKey, caCert)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		attr        admission.Attributes
		originalObj runtime.Object
		mutations   []mutateFn
		assertions  assertionFn
		err         bool
	}{
		{
			attr: admission.NewAttributesRecord(&podSpec, nil, api.Kind("Pod").WithVersion("version"), "namespace",
				"", api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			originalObj: &podSpec,
			mutations:   []mutateFn{mutatePodAnnotations},
			assertions:  verifyPodAnnotations,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&podWithNoContainers, nil, api.Kind("Pod").WithVersion("version"),
				"namespace", "", api.Resource("pods").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			originalObj: &podWithNoContainers,
			mutations:   []mutateFn{changeImageOnPodContainer},
			err:         true,
		}, {
			attr: admission.NewAttributesRecord(&namespaceSpec, nil, api.Kind("Namespace").WithVersion("version"),
				"TestNamespace", "TestNamespace", api.Resource("namespaces").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			originalObj: &namespaceSpec,
			mutations:   []mutateFn{mutateNamespace},
			assertions:  verifyMutatedNamespace,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&jobSpec, nil, api.Kind("Job").WithVersion("version"),
				"TestNamespace", "TestJob", api.Resource("jobs").WithVersion("version"), "", admission.Create, &user.DefaultInfo{}),
			originalObj: &jobSpec,
			mutations:   []mutateFn{mutateJob},
			assertions:  verifyJob,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&replicationControllerSpec, nil, api.Kind("ReplicationController").WithVersion("version"),
				"TestNamespace", "TestReplicationController", api.Resource("replicationControllers").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateReplicationController},
			assertions:  verifyReplicationController,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&replicaSetSpec, nil, api.Kind("ReplicaSet").WithVersion("version"),
				"TestNamespace", "TestReplicaSet", api.Resource("replicaSet").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateReplicaSet},
			assertions:  verifyReplicaSet,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&deploymentSpec, nil, api.Kind("Deployment").WithVersion("version"),
				"TestNamespace", "TestDeployment", api.Resource("deployments").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateDeployment},
			assertions:  verifyDeployment,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&statefulSetSpec, nil, api.Kind("StatefulSet").WithVersion("version"),
				"TestNamespace", "TestStatefulSet", api.Resource("statefulSets").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateStatefulSet},
			assertions:  verifyStatefulSet,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&daemonSetSpec, nil, api.Kind("DaemonSet").WithVersion("version"),
				"TestNamespace", "TestDaemonSet", api.Resource("daemonSets").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateDaemonSet},
			assertions:  verifyDaemonSet,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&serviceSpec, nil, api.Kind("Service").WithVersion("version"),
				"TestNamespace", "TestService", api.Resource("services").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateService},
			assertions:  verifyService,
			err:         false,
		}, {
			attr: admission.NewAttributesRecord(&ingressSpec, nil, api.Kind("Ingress").WithVersion("version"),
				"TestNamespace", "TestIngress", api.Resource("ingress").WithVersion("version"),
				"", admission.Create, &user.DefaultInfo{}),
			originalObj: &replicationControllerSpec,
			mutations:   []mutateFn{mutateIngress},
			assertions:  verifyIngress,
			err:         false,
		},
	}
	wh, err := newAdmissionWebhook(s.URL, clientCert, clientKey, caCert)
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		svc.mutations = test.mutations
		err = wh.Admit(test.attr)
		if test.err {
			if err == nil {
				t.Errorf("Expected test %d to return error but none was returned", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("expected test %d to not return error but an error was found: %v", i, err)
			continue
		}
		if len(test.mutations) > 0 {
			test.assertions(test.attr, t)
		}
	}
}

func verifyAnnotations(annotations map[string]string, t *testing.T) {
	if annotations == nil {
		t.Error("Expected attributes to not be nil")
		return
	}
	if annotations[testAnnotationKey] != testAnnotationValue {
		t.Errorf("Expected attributes to contain %v=%v, but found %+v", testAnnotationKey, testAnnotationValue,
			annotations)
	}
}

func mutatePodAnnotations(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Pod.Annotations == nil {
		ar.Spec.Object.Pod.Annotations = map[string]string{}
	}
	ar.Spec.Object.Pod.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyPodAnnotations(attributes admission.Attributes, t *testing.T) {
	pod, ok := attributes.GetObject().(*api.Pod)
	if !ok {
		t.Errorf("Expected attributes object to be a pod but found %T", attributes.GetObject())
		return
	}
	verifyAnnotations(pod.Annotations, t)
}

func changeImageOnPodContainer(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if len(ar.Spec.Object.Pod.Spec.Containers) == 0 {
		return ar, errors.New("Expected pod to have at least 1 container but found none")
	}
	ar.Spec.Object.Pod.Spec.Containers[0].Image = "centos:7"
	return ar, nil
}

func mutateNamespace(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Namespace == nil {
		return ar, errors.New("Expected namesapce to not be nil")
	}

	if ar.Spec.Object.Namespace.Annotations == nil {
		ar.Spec.Object.Namespace.Annotations = map[string]string{}
	}

	ar.Spec.Object.Namespace.Annotations["test"] = "value"
	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyMutatedNamespace(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	namespace, ok := attr.GetObject().(*api.Namespace)
	if !ok {
		t.Errorf("Expected object to be namespace but found %T", attr.GetObject())
		return
	}
	verifyAnnotations(namespace.Annotations, t)
}

var jobUpdatedParallelism = int32(10)

func mutateJob(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Job == nil {
		return ar, errors.New("Expected job to not be nil")
	}
	if ar.Spec.Object.Job.Annotations == nil {
		ar.Spec.Object.Job.Annotations = map[string]string{}
	}
	ar.Spec.Object.Job.Annotations["test"] = "value"
	ar.Spec.Object.Job.Spec.Parallelism = &jobUpdatedParallelism
	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""

	return ar, nil
}

func verifyJob(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	job, ok := attr.GetObject().(*batch.Job)
	if !ok {
		t.Errorf("Expected object to be Job but found %T", attr.GetObject())
		return
	}
	verifyAnnotations(job.Annotations, t)
	if *job.Spec.Parallelism != jobUpdatedParallelism {
		t.Errorf("Expected job spec parallelism to be updated to %d but found %d", jobUpdatedParallelism,
			*job.Spec.Parallelism)
	}
}

func mutateReplicationController(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.ReplicationController == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.ReplicationController.Annotations == nil {
		ar.Spec.Object.ReplicationController.Annotations = map[string]string{}
	}
	ar.Spec.Object.ReplicationController.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.ReplicationController.Spec.Replicas = &updatedReplicas

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyReplicationController(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	rc, ok := attr.GetObject().(*api.ReplicationController)
	if !ok {
		t.Errorf("Expected object to be a ReplicationController but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(rc.Annotations, t)
	if rc.Spec.Replicas != updatedReplicas {
		t.Errorf("Expected number of replicas to be updated to %d but found %d", updatedReplicas, rc.Spec.Replicas)
		return
	}
}

func mutateReplicaSet(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.ReplicaSet == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.ReplicaSet.Annotations == nil {
		ar.Spec.Object.ReplicaSet.Annotations = map[string]string{}
	}
	ar.Spec.Object.ReplicaSet.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.ReplicaSet.Spec.Replicas = &updatedReplicas

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyReplicaSet(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	rs, ok := attr.GetObject().(*extensions.ReplicaSet)
	if !ok {
		t.Errorf("Expected object to be a ReplicaSet but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(rs.Annotations, t)
	if rs.Spec.Replicas != updatedReplicas {
		t.Errorf("Expected replica set to have %d replicas but found %d", updatedReplicas, rs.Spec.Replicas)
		return
	}
}

func mutateDeployment(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Deployment == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.Deployment.Annotations == nil {
		ar.Spec.Object.Deployment.Annotations = map[string]string{}
	}
	ar.Spec.Object.Deployment.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.Deployment.Spec.Replicas = &updatedReplicas

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyDeployment(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	deployment, ok := attr.GetObject().(*extensions.Deployment)
	if !ok {
		t.Errorf("Expected object to be a Deployment but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(deployment.Annotations, t)
	if deployment.Spec.Replicas != updatedReplicas {
		t.Errorf("Expected deployment to have %d replicas but found %d", updatedReplicas, deployment.Spec.Replicas)
		return
	}
}

func mutateStatefulSet(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.StatefulSet == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.StatefulSet.Annotations == nil {
		ar.Spec.Object.StatefulSet.Annotations = map[string]string{}
	}
	ar.Spec.Object.StatefulSet.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.StatefulSet.Spec.Replicas = &updatedReplicas
	ar.Spec.Object.StatefulSet.Spec.ServiceName = "DifferentService"

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyStatefulSet(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	statefulSet, ok := attr.GetObject().(*apps.StatefulSet)
	if !ok {
		t.Errorf("Expected object to be a StatefulSet but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(statefulSet.Annotations, t)
	if statefulSet.Spec.Replicas != updatedReplicas {
		t.Errorf("expected statefulset to have %d replicas but found %d", updatedReplicas, statefulSet.Spec.Replicas)
	}
}

func mutateDaemonSet(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.DaemonSet == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.DaemonSet.Annotations == nil {
		ar.Spec.Object.DaemonSet.Annotations = map[string]string{}
	}
	ar.Spec.Object.DaemonSet.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.DaemonSet.Spec.Template.Spec.Hostname = "test.hostname.k8s.io"

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyDaemonSet(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	daemonSet, ok := attr.GetObject().(*extensions.DaemonSet)
	if !ok {
		t.Errorf("Expected object to be a DaemonSet but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(daemonSet.Annotations, t)
}

func mutateService(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Service == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.Service.Annotations == nil {
		ar.Spec.Object.Service.Annotations = map[string]string{}
	}
	ar.Spec.Object.Service.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.Service.Spec.ClusterIP = "192.168.1.1"
	ar.Spec.Object.Service.Spec.Type = v1.ServiceTypeLoadBalancer

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyService(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	service, ok := attr.GetObject().(*api.Service)
	if !ok {
		t.Errorf("Expected object to be a Service but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(service.Annotations, t)
	if service.Spec.ClusterIP != "192.168.1.1" {
		t.Errorf("Expected service to have clusterIP of 192.168.1.1 but found %v", service.Spec.ClusterIP)
		return
	}
	if service.Spec.Type != api.ServiceTypeLoadBalancer {
		t.Errorf("Expected service to have type of %v but found type of %v", api.ServiceTypeLoadBalancer, service.Spec.Type)
		return
	}
}

func mutateIngress(ar v1alpha1.AdmissionReview) (v1alpha1.AdmissionReview, error) {
	if ar.Spec.Object.Ingress == nil {
		return ar, errors.New("Expected replication controller to not be nil")
	}
	if ar.Spec.Object.Ingress.Annotations == nil {
		ar.Spec.Object.Ingress.Annotations = map[string]string{}
	}
	ar.Spec.Object.Ingress.Annotations[testAnnotationKey] = testAnnotationValue
	ar.Spec.Object.Ingress.Spec.Backend.ServiceName = "different-service-name"

	ar.Status.Allowed = true
	ar.Status.EvaluationError = ""
	ar.Status.Mutated = true
	ar.Status.Reason = ""
	return ar, nil
}

func verifyIngress(attr admission.Attributes, t *testing.T) {
	if attr.GetObject() == nil {
		t.Error("Expected spec object to not be nil")
		return
	}
	ingress, ok := attr.GetObject().(*extensions.Ingress)
	if !ok {
		t.Errorf("Expected object to be an ingress but found %v", attr.GetObject())
		return
	}
	verifyAnnotations(ingress.Annotations, t)
	if ingress.Spec.Backend.ServiceName != "different-service-name" {
		t.Errorf("Expected ingress to have service name of 'different-service-name' but found %q", ingress.Spec.Backend.ServiceName)
		return
	}
}

var (
	podSpec = api.Pod{
		Spec: api.PodSpec{
			Containers: []api.Container{
				{
					Image: "nginx:alpine",
					Name:  "nginx",
					Ports: []api.ContainerPort{
						{
							ContainerPort: 443,
							Name:          "HTTPS",
							Protocol:      api.ProtocolTCP,
						},
					},
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
	}

	noNamespacePodSpec = api.Pod{
		Spec: api.PodSpec{
			Containers: []api.Container{
				{
					Image: "nginx:alpine",
					Name:  "nginx",
					Ports: []api.ContainerPort{
						{
							ContainerPort: 443,
							Name:          "HTTPS",
							Protocol:      api.ProtocolTCP,
						},
					},
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
	}

	namespaceSpec = api.Namespace{
		Spec: api.NamespaceSpec{},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
	}

	parallelism = int32(4)

	jobSpec = batch.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestJob",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: batch.JobSpec{
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
			Parallelism: &parallelism,
		},
	}

	initialReplicas           = int32(3)
	updatedReplicas           = int32(10)
	replicationControllerSpec = api.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestReplicationController",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: api.ReplicationControllerSpec{
			Replicas: initialReplicas,
			Template: &api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
		},
	}

	replicaSetSpec = extensions.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestReplicaSet",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.ReplicaSetSpec{
			Replicas: initialReplicas,
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
		},
	}

	deploymentSpec = extensions.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestDeployment",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.DeploymentSpec{
			Replicas: initialReplicas,
			Paused:   false,
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
		},
	}

	noNamespaceDeploymentSpec = extensions.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestDeployment",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.DeploymentSpec{
			Replicas: initialReplicas,
			Paused:   false,
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
		},
	}

	statefulSetSpec = apps.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestStatefulSet",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: apps.StatefulSetSpec{
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
			Replicas:    initialReplicas,
			ServiceName: "StatefulSetService",
		},
	}

	daemonSetSpec = extensions.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestDaemonSet",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.DaemonSetSpec{
			Template: api.PodTemplateSpec{
				Spec: podSpec.Spec,
			},
		},
	}

	serviceSpec = api.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestService",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: api.ServiceSpec{
			ClusterIP:    "10.0.0.1",
			ExternalName: "test.svc.k8s.io",
			Type:         api.ServiceTypeClusterIP,
		},
	}

	noNamespaceServiceSpec = api.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestService",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: api.ServiceSpec{
			ClusterIP:    "10.0.0.1",
			ExternalName: "test.svc.k8s.io",
			Type:         api.ServiceTypeClusterIP,
		},
	}

	ingressSpec = extensions.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestIngress",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.IngressSpec{
			Backend: &extensions.IngressBackend{
				ServiceName: "TestServiceBackend",
			},
		},
	}

	noNamespaceIngressSpec = extensions.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "TestIngress",
			Namespace:   "TestNamespace",
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: extensions.IngressSpec{
			Backend: &extensions.IngressBackend{
				ServiceName: "TestServiceBackend",
			},
		},
	}

	podWithNoContainers = api.Pod{
		Spec: api.PodSpec{},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
	}

	serverKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyhmjG7BJCGwuf1FyHJtq9iUXZ3oymtrOHdaSAcsCSxFrUJTH
riPOe9d1ahH7bvsZycnzh7/pABdTDUdStiR8/1KUYt8PjjosrmmYyupqNPq+wkBD
EmKa+4voR2EBgXbIGghx8e++KmmNnSCNk6B8m2EJR0fn9zPnoY3uHNogKjCICt19
g+uipuwZco7yTu3e40LwpIVmA8SsrM0S/CaZqSmtIClSwv7YDvreUd6FuI/GT0cj
NMPRuSdfohBxGz6R7Cml7qP4AYKajjl+08mRYv3o+hVclXUltcRmTnJanYGmGS3k
C7KiE2sHINzF2qUUAoO+yXpMx7QtK+NS0PhjmQIDAQABAoIBAFOicmZ1+HM82a0k
llWSV5xPUzUmU6TT4bJlZnzJd0R7i+6H8250MPH9AwEHOgb+cPiZ02cdGx5HiL4Z
AviPdw7uLKwR5U0VdAIlfu6SPat5DNI0Z81G8x4gEtrfIRFjh4GGdykI7qh8j/cz
ToOGSaq/aGiQMEWTvEqWArD7742lVHE4/1bM3GuKV8shy31zfw0d9RCCy1GdBR75
zZ1w4zKL55DM3PC73Ndy2IcrViVXVAgfqD0xxKwQW1qoENgThueALj3PkU1XaKxI
nOdztt1fBFpcSHyFBkJ1sexumnssMRXSVcJ/0D5F2T4QPUnWBM0oSzoyioAab4RP
8XrZwAECgYEA/eFjNgCeHztXgS3YRC/RddLOtobrerYKN7vA64ou5VUCqEQ9rfQE
MbmKdZdiFVNJI0JrPq8Gx39ME9g2OLTVVqdtlm6JYjy5CHdUXHIHObo9oz7Uueos
TdeCf0LFvEUNXvbGIP5KqcdVi+wekauHMqXGQYTNa6bar/FE99MdyAECgYEAy8mU
tCjm4QsuKsdku5bDHGv56ZN9DkWd7Lcjie5otElwH9bKfIQ2lUYyoUAIa0rEJ9Ya
7vuAZ2bX7od9s8Jkci91ONDWxdy361SRZcbpuqgQKKVRuzGlfamufyW4sStbXY1k
+zeQxyWGJHhhLWpapzca89RELGZSkbIMVVIT25kCgYEA7EUYboZuoYQ5cGf476RM
28kfRXEUrvPBWJLr/IhyEk1mFrDDciM40AnrWHpU9qG23BCQ/BopRforFADQnT91
l5pje29NfdYjIUTkhtA79zZi7IyprofHSX453TOIECl3QxyH0Oa3F4ACFiDdZhXq
0XDDq+/quLfkp37y/2xDOAECgYEAmi55g5UumTWMSHFzlToLhIVtH3unMhUZ1u74
xHLMZRrq6ivoJy0g3u+tfrKjrAl1P26OEiHWlGULGj0Ireh1dq7RUZsv46OKw1HI
b+h/Den5z8bEf4ygWOL4UtqHUgQrrCw+KpNvxjxtsUoiu+mrjLf0fGYs7iq8bd73
1dWzkIECgYEAi6P/LzMC6orbyONmwlscqO1Ili8ZBkUjJ/wThkiNMMA3pyKmb68W
yt56Yh0rs+WnuVUN90cG87k+CY35dQ7FAOVUJi9LWGA3Oq9fGkoOB7f4dzaUu/rB
dtit2KPCxiKpZsxqSf4+S8AXYF48abNPLYK3DCCSqAah09gYOrqYlW4=
-----END RSA PRIVATE KEY-----`)

	serverCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIJAMvo2rkGpEUQMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFndlYmhvb2tfaW1hZ2Vwb2xpY3lfY2EwIBcNMTYwODEyMjAyMjUwWhgPMjI5
MDA1MjgyMDIyNTBaMCUxIzAhBgNVBAMUGndlYmhvb2tfaW1hZ2Vwb2xpY3lfc2Vy
dmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhmjG7BJCGwuf1Fy
HJtq9iUXZ3oymtrOHdaSAcsCSxFrUJTHriPOe9d1ahH7bvsZycnzh7/pABdTDUdS
tiR8/1KUYt8PjjosrmmYyupqNPq+wkBDEmKa+4voR2EBgXbIGghx8e++KmmNnSCN
k6B8m2EJR0fn9zPnoY3uHNogKjCICt19g+uipuwZco7yTu3e40LwpIVmA8SsrM0S
/CaZqSmtIClSwv7YDvreUd6FuI/GT0cjNMPRuSdfohBxGz6R7Cml7qP4AYKajjl+
08mRYv3o+hVclXUltcRmTnJanYGmGS3kC7KiE2sHINzF2qUUAoO+yXpMx7QtK+NS
0PhjmQIDAQABo0AwPjAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUEDDAK
BggrBgEFBQcDATAPBgNVHREECDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCF
xaS/KIijKDLbaL/P7AxhnAta8jYSEzL66WTaYV4GeRhLtX/vPUV9gzPWnkNr0TBM
lS+Q0KDxh17rJ/MrWwrMSwsgKZahTR+7mSHiXrIlHcnHXXSvhnoXu8VDu8goqOEI
5yRHt6plzmFZEwVi/hSmIAuQjmyjOk2dc/ZKI0fMExKhnVms8AoztjAMbt3TFMTK
Kk7bVGPblFsXiVPhRlzbLbh5i/PvHHf+12ACrVxoxOOQUmuXy1DPxmkk7jP3FIsE
+rnyWnfmGS5sW8oMkj2nFYIh3LehADsMS9s7JVlJk/loNJDA9Yn2fev/vRKck8RZ
siw54G4e+6nKpY5BAY1M
-----END CERTIFICATE-----`)

	caKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoKjaP9PtRAGRNCx8z+0LTGt2eEduqElcPrm8EvlBwn3dnLFo
55x+Tejb6ysQsyy1BKI0dRdX4tNSAgFFFaIVcsOo9kGtPq7QsSd4VWViNE3L5zJA
+0X2ztHBkPlQXwDrtArsNKxwcpyHP9sXE05BN36XBjAz2XkusTkFrdJ/PzjZhlb4
9i9gTZ0bJbexQ1+dfZX2WpY70JypYnKrbV1dLj5ORb65SC8IWZcG/ouqLWAN+lT+
eug8P6PjoOQWs3qsl0bSAtAdiYcwXKtPiBEWPJe24ACywyE+8jVzmIJqAm0U1V8k
GTHzjmSRwzgX/VN5JMri/nxNIW5UsbhHzYHfjQIDAQABAoIBAQCIeAWz1Bwl+ULT
U7rNkChZyKrAbsUDdBVEPtcQMuR2Bh5Z/KUEoHz1RwiP0WwFFsPI5NO0ZpjD1wdB
Jrz9LEoVyzfZvl4f8bTZ1pIzz8PEdBTxFVH3Xy3P7oMC15Q6rviIXgLYl2WJJYcJ
adxHDOD+96vnmMhiQbq01aAKT9TA6PvXXDusfadMQ+il+mEbeZz4aNYBk9u+34Co
aQTNwlLft5anW2820IMJdJR/bFjyX71cPID1rIjw4VOQZExIpIEnuHPiulyE4EvJ
hvvVKAm0dRjHg39cz0eAQ6PntX3DUvjNfcLLrj7sQxLco1cnAKZxhpZ8ajtvynr5
pF2d5xYBAoGBAM8y/e5+raHTLHEKZUc0vekUey3fc4aRqptyAKTS0ZvOYBXg4Vhl
mOK7066IEqwF4UHGmQqW6D5HstqPGx0uN0d9IyImUqDp0JotdFSZMEMQkYLyFD+r
J7O2nOO6E4SOxXO9/q9iSB+G/qgl6LS3O9+58uHTYEbUommiDZ6a18qBAoGBAMZ/
xSGMa3b6vrU3rUTEh+xBh6YRVNYAxWwpGg2sO0k2brT3SxSMCrx1wvNGY+k7XNx0
JJfZQDC/wlR0rcVTnPCi/cE9FTUlh23xXCPRlxwc4vLly+7yU95LhAO+N9XAwsrs
OIi4lR57jxoLNO2ofoAVMvllkE5Eo5W6lOPR2xcNAoGAV1Tv0OFV//pJJhAypfOm
BCLc1HX1dIfbOA+yE8bEEH7I4w/ZC3AvI4n1a//wls8Xpai2gs8ebnm7+gENdZww
MpKdB1zNwQMsKH/2I146CFpoap/sRvW2EzpqIFYiueGPefxf575uFdPJbEgmMF13
ABKZO/PjBZfEKO/j+7DaOYECgYBYX+Zqa1QlIrnpgKJZ7Y3+d6ZnH2w/4xQCdcIt
uDKlA+ECHN+GhFr7UQq8uOgenNlZJTRtjsHvclCYvWHoarOCx25mrEVW5iCHqF+3
asb2Mz4vmnPTLHx+iex6piPBvRJ8ufLpnBR3/9bUZ4znCo9XgxiwxLEcx551OR60
12fNuQKBgC1fkqgtDDxQzrabSmmiqXthcPXxFdsYqnSNlFgba0uaAp9LREztSrX8
QhwSoSwHVmjBvR6SybLYdsZ9Efj/w7XBejOOcS44MOoHYYFdsP7W47Ao5QFqvDoI
oqyQ1R73cF9WX6obRQwH4P3DvcsBebOjvjMX9mljKtpJMc9KqrGc
-----END RSA PRIVATE KEY-----`)

	caCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIJAJlL10mfdZraMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFndlYmhvb2tfaW1hZ2Vwb2xpY3lfY2EwIBcNMTYwODEyMjAyMjUwWhgPMjI5
MDA1MjgyMDIyNTBaMCExHzAdBgNVBAMMFndlYmhvb2tfaW1hZ2Vwb2xpY3lfY2Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgqNo/0+1EAZE0LHzP7QtM
a3Z4R26oSVw+ubwS+UHCfd2csWjnnH5N6NvrKxCzLLUEojR1F1fi01ICAUUVohVy
w6j2Qa0+rtCxJ3hVZWI0TcvnMkD7RfbO0cGQ+VBfAOu0Cuw0rHBynIc/2xcTTkE3
fpcGMDPZeS6xOQWt0n8/ONmGVvj2L2BNnRslt7FDX519lfZaljvQnKlicqttXV0u
Pk5FvrlILwhZlwb+i6otYA36VP566Dw/o+Og5BazeqyXRtIC0B2JhzBcq0+IERY8
l7bgALLDIT7yNXOYgmoCbRTVXyQZMfOOZJHDOBf9U3kkyuL+fE0hblSxuEfNgd+N
AgMBAAGjUDBOMB0GA1UdDgQWBBSx2m5pJoFpdGDmOzSVl29jkheQFTAfBgNVHSME
GDAWgBSx2m5pJoFpdGDmOzSVl29jkheQFTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQBe6tZzmOQKt8fTsnDDKvEjSwK2Pb91R5tkwmIhdpTjmAgC+Zkk
kSihR9sZIxdRC4wlbuorRl8BjhX5I8Kr3FWdDhOrIhicp7CIrxPiFh6+ZLSOj3o9
pQ6SriIopjXCHvl5XjzKxLg/uQpzui/YUtfqffCRB4EccOsjlyUanK5rjMLBMLCn
2LadiRB2Q/cC9fYigczETACDjq5vzp6I9eqwpCTmv/+4bFncW+VBD4touaJc8FKf
ljW5xekKRh4uzP85X7rEgrFen/my5Fs/cylkFvYIiZwgn6NLgW3BNi+m31XIfU0S
xIbgh4UH0dwc6Zk8WUwFud4GXj6OyGneMGKB
-----END CERTIFICATE-----`)
)

var clientKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3IOqCz88jTQpsGIBFTdjbqBg+0NFeym3OEl8zLfzkLQuZieO
3AoFMiLaeYgC4m9BBsdJWSXRzWcqgVWIY8KU7c2SPfErlhP86VFoD0RKHJxwRVh0
y70WyK8+CzzwrrPpWydgtAwbm9F+0v/zdcCL0TEL2/MYgCc97mSGwtTRaW4bqq6V
MWMHBcOu44dHq8+CF8ixxk0WSBl2oocXnF7QdEA15iuOM5hacLB0fyH4T3NM54lO
rOSXUMUuysougSrMcCPv3esFlv4TVUkldwu73jWx+Wja0gNXlnmgU2lqFdM+PsVT
DPMzoHTEhIGPIWO5anYR5Qv0SmX3nXkNcx9QDQIDAQABAoIBADblRCC2pmFUmghB
7ZkVh9hTbrE+Zv6pPOZzTPE93hGo+WAO+v6GNBLuIEte87DhF2QTmovp4VfsFeXK
oECNgTvOEFkBP+OFqFGBJZGfY3/J5h0tTy4lLZXaImzzx8sGGNLLc8R+uyTIO3VV
qIso2uXB+vzPgMrueflt5yp7hoJjI0c+qEktUg5n+WJFAFteI9LCngN+xwRWVEgp
rjKVPcT9zio8tLJOhcSPA7q6lORUkwbPWHyNDpamvldnqjhgp5Ceq5f/qfoWPzvM
H5o72Ax2WduxST+P+hCOqZReUmTaGzAKb5rJwdEpmbnDZ3kSR08aT/40m/EG1SvQ
pi0b3QECgYEA/mRGIjaYPQr+tw3Sz8g76t3PYfrglro60HdLBn2IUpj2sEpazNId
2aPFPb58whL+VPmUfXbpPH+wW/+wWpRw4MraFkJanbOjDiEGXK5ZoUQIDZJWUSwf
oCge5uacU69weC67UyPYmK1e+A/gaFw1Dz729jLxtB3rGWKxEGbWEc0CgYEA3eiP
hv0GxbdEEbSfQoSPKbBHGI9spaqAIcqL+dSsx3m6Ckqx0El/xi9mQkITgqs2gyqI
o2T/3yDli9oF4+3Plz0wrZ11auOWX+nhKfACtF679I1PL0UOavXF0FVgOfwOIqdG
jp4QQV7USkbTP9ZOHo90Y8G4rmTEdMZ/VsH490ECgYEA8u/bsiyk8haf7Tx8SAWW
gtLUi2NEO20ZYZ+qvEYBe6+sVeqMD/HQo9ksMazKA6ST0Z6O2cpHLolaaGEjjz0X
FvVhk8RGOTglzQZoxvWRjtojPqKzX81dXlsyN5ufSqPOKlemeN1QqW1XtlmjGsaD
vU2KFs/L1xCDRbjkEx/B6zkCgYBmqeE9InKvpknnpxjHPWy+bL93rWMmgesltv9r
ZelJoBdiC4yYQGjM18EHhmpgWbWumU79yQxXvnB0czmmaa9Q2Q5cRCy+duxrE1kI
ffHCYNG0ImwwAlLZSTtrVxRdvy8K+Ti7YoVCuQyeEIZLUmpx2QyP2mAGzrfVDsB6
8uKsAQKBgQDO+PmADra91NKJP1iVuvOK8iEy/Z14L03uKtF3X9u8vLdzQZa/Q/P9
hXOX9ovFwSBQOOfgb+/+QRuPL4xxi1J8CFwrSWCEeFgrDijl9DS6aNY6BWHDA8p6
8V7Adb04cnenj8QjYYN8/mqsQlHSoAIxeAlUoJpq+pk7O8PAfbjgMw==
-----END RSA PRIVATE KEY-----`)

var clientCert = []byte(`-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIJAMvo2rkGpEURMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFndlYmhvb2tfaW1hZ2Vwb2xpY3lfY2EwIBcNMTYwODEyMjAyMjUwWhgPMjI5
MDA1MjgyMDIyNTBaMCUxIzAhBgNVBAMUGndlYmhvb2tfaW1hZ2Vwb2xpY3lfY2xp
ZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3IOqCz88jTQpsGIB
FTdjbqBg+0NFeym3OEl8zLfzkLQuZieO3AoFMiLaeYgC4m9BBsdJWSXRzWcqgVWI
Y8KU7c2SPfErlhP86VFoD0RKHJxwRVh0y70WyK8+CzzwrrPpWydgtAwbm9F+0v/z
dcCL0TEL2/MYgCc97mSGwtTRaW4bqq6VMWMHBcOu44dHq8+CF8ixxk0WSBl2oocX
nF7QdEA15iuOM5hacLB0fyH4T3NM54lOrOSXUMUuysougSrMcCPv3esFlv4TVUkl
dwu73jWx+Wja0gNXlnmgU2lqFdM+PsVTDPMzoHTEhIGPIWO5anYR5Qv0SmX3nXkN
cx9QDQIDAQABoy8wLTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUEDDAK
BggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAkHIhrPfRROhzLg2hRZz5/7Kw
3V0/Y0XS91YU3rew+c2k++bLp1INzpWxfB6gbSC6bTOgn/seIDvxwJ2g5DRdOxU/
Elcpqg1hTCVfpmra9PCniMzZuP7lsz8sJKj6FgE6ElJ1S74FW/CYz/jA+76LLot4
JwGkCJHzyLgFPBEOjJ/mLYSM/SDzHU5E+NHXVaKz4MjM3JwycN/juqi4ikAcZEBW
1HmpcHKBedAwlCM90zlvG2SL4sFRp/clMbntRdmh5L+/1F6aP82PO3iuvXtXP48d
NtjboxP3IV2eY5iUle8BOQ9CnFQs4wsF1LxTMNACypQyFinMsHrCpwrB3i4VvA==
-----END CERTIFICATE-----`)

