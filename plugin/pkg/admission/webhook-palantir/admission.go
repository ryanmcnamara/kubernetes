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
	"fmt"
	"io"

	"github.com/golang/glog"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	restclient "k8s.io/client-go/rest"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/delegatedadmission"

	_ "k8s.io/kubernetes/pkg/apis/delegatedadmission/install"
	_ "k8s.io/kubernetes/pkg/api/install"
	_ "k8s.io/kubernetes/pkg/apis/apps/install"
	_ "k8s.io/kubernetes/pkg/apis/extensions/install"
	"k8s.io/kubernetes/pkg/apis/delegatedadmission/v1alpha1"
)

var (
	// Ensure Webhook implements the admission.Interface interface
	_ admission.Interface = (*WebhookAdmissionController)(nil)

	// TODO is this comment bad?
	// Use the extensions v1beta1 for a group here, because there is no admissions v1beta1
	groupVersions = []schema.GroupVersion{v1alpha1.SchemeGroupVersion}
)

// Register registers a plugin
func Register(plugins *admission.Plugins) {
	plugins.Register("Webhook", func(configFile io.Reader) (admission.Interface, error) {
		plugin, err := New(configFile)
		if err != nil {
			return nil, err
		}

		return plugin, nil
	})
}

type WebhookAdmissionController struct {
	gw             *webhook.GenericWebhook
	imageWhitelist map[string]struct{}
}

func New(configFile io.Reader) (*WebhookAdmissionController, error) {
	config := AdmissionConfig{}
	d := yaml.NewYAMLOrJSONDecoder(configFile, 4096)
	err := d.Decode(&config)
	if err != nil {
		return nil, err
	}

	backoffDuration, err := config.Webhook.RetryBackoffDuration()
	if err != nil {
		return nil, err
	}
	gw, err := webhook.NewGenericWebhook(api.Registry, api.Codecs, config.Webhook.KubeConfigFile, groupVersions, backoffDuration)
	if err != nil {
		return nil, err
	}
	whController := &WebhookAdmissionController{
		gw:             gw,
		imageWhitelist: make(map[string]struct{}, len(config.Webhook.WhitelistImages)),
	}
	for _, image := range config.Webhook.WhitelistImages {
		whController.imageWhitelist[image] = struct{}{}
	}

	return whController, nil
}

// Admit makes an admission decision based on the request attributes by making a REST request to the remote service
// describing the admissions request as described by the admission.Attributes. The format of the request is dependent
// on the type of resource being considered for admission. An example request body for a Pod is:
/*
 {
   "apiVersion": "delegatedadmission.k8s.io/v1alpha1",
   "kind": "AdmissionReview",
   "spec": {
     "spec": {
       "metadata": {
         "creationTimestamp": null
       },
       "spec": {
         "volumes": null,
         "containers": [
            {
              "name": "nginx",
              "image": "nginx:alpine",
            }
        ],
      },
      "status": {}
     },
   },
   "user": {
     "user": "admin",
     "groups": ["root"],
     "extras": []
   }
 }

The remote service is expected to fill the AdmissionReviewStatus field to either allow ro disallow admission.
Additionally, the remote service may mutate the provided object in any way it likes, so long as the type and apiVersion
remains the same. If the remote service mutates the object, it must indicate the mutation in the AdmissionReviewStatus
field in the response. A permissive response would return:

  {
   "apiVersion": "delegatedadmission.k8s.io/v1alpha1",
   "kind": "AdmissionReview",
   "spec": {
     "spec": {
       "metadata": {
         "creationTimestamp": null
       },
       "spec": {
         "volumes": null,
         "containers": [
            {
              "name": "nginx",
              "image": "nginx:alpine",
            }
        ],
      },
      "status": {}
     },
   },
   "user": {
     "user": "admin",
     "groups": ["root"],
     "extras": []
   },
   "status": {
     "allowed": true,
     "mutated": false,
   }
 }

To disallow admission, the remote service would return:

 {
   "apiVersion": "delegatedadmission.k8s.io/v1alpha1",
   "kind": "AdmissionReview",
   "spec": {
     "spec": {
       "metadata": {
         "creationTimestamp": null
       },
       "annotations": {
         "com.palantir.rubix.spp/path": "/slate"
       },
       "spec": {
         "volumes": null,
         "containers": [
            {
              "name": "nginx",
              "image": "nginx:alpine",
            }
        ],
      },
      "status": {}
     },
   },
   "user": {
     "user": "admin",
     "groups": ["root"],
     "extras": []
   },
   "status": {
     "allowed": false,
     "reason": "Pod not permitted to include annotation of com.palantir.rubix.spp/path
   }
 }
*/
func (w *WebhookAdmissionController) Admit(attributes admission.Attributes) (err error) {
	userInfo := attributes.GetUserInfo()
	username := ""
	groups := []string{}
	extras := map[string]delegatedadmission.ExtraValue{}
	if userInfo != nil {
		username = userInfo.GetName()
		groups = userInfo.GetGroups()
		extras = convertToSARExtra(userInfo.GetExtra())
	}
	admissionReview := &delegatedadmission.AdmissionReview{
		Spec: delegatedadmission.AdmissionReviewSpec{
			User:      username,
			Groups:    groups,
			Extra:     extras,
			Operation: delegatedadmission.Operation(attributes.GetOperation()),
			Namespace: attributes.GetNamespace(),
			Name: attributes.GetName(),
		},
	}

	includeOldObj := false
	includeNewObj := false
	switch attributes.GetOperation() {
	case admission.Create:
		includeNewObj = true
	case admission.Update:
		includeNewObj = true
		includeNewObj = true
	case admission.Delete:
		includeNewObj = true
	case admission.Connect:
		// NO-OP on connect admissions
		return nil
	}

	objProcessor, ok := objectProcessors[attributes.GetKind().Kind]
	if !ok {
		return nil
	}
	admissionReview.Spec.Kind = attributes.GetKind().Kind

	if includeNewObj {
		admissionReview.Spec.Object = objProcessor.NewAdmissionReviewObject(attributes.GetObject())
	}
	if includeOldObj {
		admissionReview.Spec.OldObject = objProcessor.NewAdmissionReviewObject(attributes.GetOldObject())
	}

	switch obj := attributes.GetObject().(type) {
	case *api.Pod:
		if w.podWhitelisted(obj) {
			return nil
		}
	}

	if err = w.doAdmit(attributes, admissionReview); err != nil {
		return err
	}
	if !admissionReview.Status.Allowed {
		return fmt.Errorf("Operation not allowed: %s", admissionReview.Status.Reason)
	}
	if admissionReview.Status.Mutated {
		objProcessor.MutateAttributes(attributes, admissionReview.Spec.Object)
	}

	return nil
}

func (w *WebhookAdmissionController) doAdmit(attributes admission.Attributes, admissionReview runtime.Object) error {
	result := w.gw.WithExponentialBackoff(func() restclient.Result {
		return w.gw.RestClient.Post().
			Body(admissionReview).
			Do()
	})
	if err := result.Error(); err != nil {
		return w.webhookError(attributes, err)
	}
	var statusCode int
	if result.StatusCode(&statusCode); statusCode < 200 || statusCode >= 300 {
		return w.webhookError(attributes, fmt.Errorf("Error contacting webhook: %d", statusCode))
	}
	if err := result.Into(admissionReview); err != nil {
		return w.webhookError(attributes, err)
	}
	return nil
}

// Handles returns true if this admission controller can handle the given operation
// where operation can be one of CREATE, UPDATE, DELETE, or CONNECT
func (w *WebhookAdmissionController) Handles(operation admission.Operation) bool {
	// TODO why don't we handle delete?
	switch operation {
	case admission.Create, admission.Update:
		return true
	default:
		return false
	}
}

func (w *WebhookAdmissionController) podWhitelisted(pod *api.Pod) bool {
	if len(pod.Spec.Containers) == 1 {
		for _, container := range pod.Spec.Containers {
			if _, ok := w.imageWhitelist[container.Image]; ok {
				// Admit based on container having a white listed image
				return true
			}
		}
	}
	return false
}

// webhookError is a function to call on webhook failure; behavior determined by defaultAllow flag
func (w *WebhookAdmissionController) webhookError(attributes admission.Attributes, err error) error {
	if err != nil {
		glog.V(2).Infof("error contacting webhook backend: %s", err)
		return admission.NewForbidden(attributes, err)
	}
	return nil
}

func convertToSARExtra(extra map[string][]string) map[string]delegatedadmission.ExtraValue {
	if extra == nil {
		return nil
	}
	ret := map[string]delegatedadmission.ExtraValue{}
	for k, v := range extra {
		ret[k] = delegatedadmission.ExtraValue(v)
	}

	return ret
}

