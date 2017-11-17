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
#!/bin/bash

# This script builds an RPM of all of the core Kubernetes binaries

set -o errexit
set -o nounset
set -o pipefail

source "$(dirname $0)/script_functions.sh"

KUBE_ROOT=$(cd $(dirname "${BASH_SOURCE}")/../.. && pwd)

function palantir::release::package_rpm() {
    local bindir=$KUBE_ROOT/_output/dockerized/bin/linux/amd64/
    local rpmpkg=$KUBE_ROOT/_output/release-tars/kubernetes-bin.rpm
    mkdir -p "$(dirname "$rpmpkg")"

    fpm -s dir -t rpm \
        --name    kubernetes-bin \
        --version $(git_version) \
        --prefix  /usr/local/bin/ \
        --rpm-os  linux \
        --package "$rpmpkg" \
        --chdir   "$bindir" \
        kube-apiserver kube-controller-manager kube-proxy kube-scheduler kubectl kubelet
}
