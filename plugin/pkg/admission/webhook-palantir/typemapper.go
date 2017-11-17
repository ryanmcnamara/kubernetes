package webhook_palantir

import (
	"k8s.io/apiserver/pkg/admission"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/delegatedadmission"
	"k8s.io/kubernetes/pkg/apis/extensions"
)

type objectProcessor interface {
	NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject
	MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject)
}

var (
	objectProcessors = map[string]objectProcessor{
		"Pod":       &podProcessor{},
		"Namespace": &namespaceProcessor{},
		"Job":       &jobProcessor{},
		"ReplicationController": &replicationControllerProcessor{},
		"ReplicaSet":            &replicaSetProcessor{},
		"Deployment":            &deploymentProcessor{},
		"StatefulSet":           &statefulSetProcessor{},
		"DaemonSet":             &daemonSetProcessor{},
		"Service":               &serviceProcessor{},
		"Ingress":               &ingressProcessor{},
	}
)

// mutateObjectMetadata mutates attributes.GetObject() with the values of src
func mutateObjectMetadata(attributes admission.Attributes, src metav1.Object) {
	if attributes.GetObject() == nil {
		return
	}
	objMeta, ok := attributes.GetObject().(metav1.Object)
	if !ok {
		return
	}
	objMeta.SetAnnotations(src.GetAnnotations())
	objMeta.SetLabels(src.GetLabels())
	objMeta.SetName(src.GetName())
	objMeta.SetNamespace(src.GetNamespace())
}

// podProcessor is an objectProcessor for api.Pod
type podProcessor struct{}

func (p *podProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Pod: obj.(*api.Pod)}
}

func (p *podProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Pod)
	dst := attributes.GetObject().(*api.Pod)
	dst.Spec = admissionReviewObj.Pod.Spec
}

// namespaceProcessor is an objectProcessor for api.Namespace
type namespaceProcessor struct{}

func (p *namespaceProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Namespace: obj.(*api.Namespace)}
}

func (p *namespaceProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Namespace)
	dst := attributes.GetObject().(*api.Namespace)
	dst.Spec = admissionReviewObj.Namespace.Spec
}

// jobProcessor is an objectProcessor for batch.Job
type jobProcessor struct{}

func (p *jobProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Job: obj.(*batch.Job)}
}

func (p *jobProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Job)
	dst := attributes.GetObject().(*batch.Job)
	dst.Spec = admissionReviewObj.Job.Spec
}

// replicationControllerProcessor is an objectProcessor for api.ReplicationController
type replicationControllerProcessor struct{}

func (p *replicationControllerProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{ReplicationController: obj.(*api.ReplicationController)}
}

func (p *replicationControllerProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.ReplicationController)
	dst := attributes.GetObject().(*api.ReplicationController)
	dst.Spec = admissionReviewObj.ReplicationController.Spec
}

// replicaSetProcessor is an objectProcessor for extensions.ReplicaSet
type replicaSetProcessor struct{}

func (p *replicaSetProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{ReplicaSet: obj.(*extensions.ReplicaSet)}
}

func (p *replicaSetProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.ReplicaSet)
	dst := attributes.GetObject().(*extensions.ReplicaSet)
	dst.Spec = admissionReviewObj.ReplicaSet.Spec
}

// deploymentProcessor is an objectProcessor for extensions.Deployment
type deploymentProcessor struct{}

func (p *deploymentProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Deployment: obj.(*extensions.Deployment)}
}

func (p *deploymentProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Deployment)
	dst := attributes.GetObject().(*extensions.Deployment)
	dst.Spec = admissionReviewObj.Deployment.Spec
}

// statefulSetProcessor is an objectProcessor for apps.StatefulSet
type statefulSetProcessor struct{}

func (p *statefulSetProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{StatefulSet: obj.(*apps.StatefulSet)}
}

func (p *statefulSetProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.StatefulSet)
	dst := attributes.GetObject().(*apps.StatefulSet)
	dst.Spec = admissionReviewObj.StatefulSet.Spec
}

// daemonSetProcessor is an objectProcessor for extensions.DaemonSet
type daemonSetProcessor struct{}

func (p *daemonSetProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{DaemonSet: obj.(*extensions.DaemonSet)}
}

func (p *daemonSetProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.DaemonSet)
	dst := attributes.GetObject().(*extensions.DaemonSet)
	dst.Spec = admissionReviewObj.DaemonSet.Spec
}

// serviceProcessor is an objectProcessor for api.Service
type serviceProcessor struct{}

func (p *serviceProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Service: obj.(*api.Service)}
}

func (p *serviceProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Service)
	dst := attributes.GetObject().(*api.Service)
	dst.Spec = admissionReviewObj.Service.Spec
}

// ingressProcessor is an objectProcessor for extensions.Ingress
type ingressProcessor struct{}

func (p *ingressProcessor) NewAdmissionReviewObject(obj runtime.Object) *delegatedadmission.AdmissionReviewObject {
	return &delegatedadmission.AdmissionReviewObject{Ingress: obj.(*extensions.Ingress)}
}

func (p *ingressProcessor) MutateAttributes(attributes admission.Attributes, admissionReviewObj *delegatedadmission.AdmissionReviewObject) {
	mutateObjectMetadata(attributes, admissionReviewObj.Ingress)
	dst := attributes.GetObject().(*extensions.Ingress)
	dst.Spec = admissionReviewObj.Ingress.Spec
}

