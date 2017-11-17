#!/bin/bash
# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Overrides KUBE_*_PLATFORMS variables defined in hack/lib/golang.sh to
# only linux/amd64 to save on build time.
target_platforms=(
    linux/amd64
  )

# Currently mirrors KUBE_*_TARGETS variables defined in hack/lib/golang.sh.
kube_server_targets=(
    cmd/kube-proxy
    cmd/kube-apiserver
    cmd/kube-controller-manager
    cmd/cloud-controller-manager
    cmd/kubelet
    cmd/kubeadm
    cmd/hyperkube
    vendor/k8s.io/kube-aggregator
    vendor/k8s.io/apiextensions-apiserver
    plugin/cmd/kube-scheduler
  )

kube_client_targets=(
    cmd/kubectl
    federation/cmd/kubefed
  )

kube_test_targets=(
    cmd/gendocs
    cmd/genkubedocs
    cmd/genman
    cmd/genyaml
    cmd/genswaggertypedocs
    cmd/linkcheck
    federation/cmd/genfeddocs
    vendor/github.com/onsi/ginkgo/ginkgo
    test/e2e/e2e.test
  )

kube_test_server_targets=(
  cmd/kubemark
  vendor/github.com/onsi/ginkgo/ginkgo
  test/e2e_node/e2e_node.test
)
