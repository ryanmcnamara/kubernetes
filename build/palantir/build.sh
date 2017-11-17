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

# This file is a custom version of build/release.sh, which limits the
# target platforms being built to the targets declared in build/palantir/targets.sh
# (specifically, linux/amd64 only). This cuts build times in CircleCI roughly in half.
# See details in comments below.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${KUBE_ROOT}/build/common.sh"
source "${KUBE_ROOT}/build/lib/release.sh"

# Incorporate declared build targets
source "${KUBE_ROOT}/build/palantir/targets.sh"
# Incorporate custom RPM function
source "${KUBE_ROOT}/build/palantir/package_rpm.sh"
# Incorporate custom tarball package functions to limit target architectures
source "${KUBE_ROOT}/build/palantir/package_tarballs.sh"

KUBE_RELEASE_RUN_TESTS=${KUBE_RELEASE_RUN_TESTS-y}

kube::build::verify_prereqs
kube::build::build_image

# Custom instructions that replace commands in hack/make-rules/cross.sh. Commands are
# identical except that they limit targets and platforms to linux/amd64.
echo "Building binaries..."
kube::build::run_build_command make all WHAT="${kube_server_targets[*]}" KUBE_BUILD_PLATFORMS="${target_platforms[*]}"
kube::build::run_build_command make all WHAT="${kube_client_targets[*]}" KUBE_BUILD_PLATFORMS="${target_platforms[*]}"
kube::build::run_build_command make all WHAT="${kube_test_targets[*]}" KUBE_BUILD_PLATFORMS="${target_platforms[*]}"
kube::build::run_build_command make all WHAT="${kube_test_server_targets[*]}" KUBE_BUILD_PLATFORMS="${target_platforms[*]}"

if [[ $KUBE_RELEASE_RUN_TESTS =~ ^[yY]$ ]]; then
  kube::build::run_build_command make test KUBE_BUILD_PLATFORMS="${target_platforms[*]}"
  kube::build::run_build_command make test-integration KUBE_BUILD_PLATFORMS="${target_platforms[*]}"
fi

kube::build::copy_output

if [[ "${FEDERATION:-}" == "true" ]];then
    (
	source "${KUBE_ROOT}/build/util.sh"
	# Write federated docker image tag to workspace
	kube::release::semantic_image_tag_version > "${KUBE_ROOT}/federation/manifests/federated-image.tag"
    )
fi

# Custom version of tarball packaging function to limit platforms to linux/amd64
palantir::release::package_tarballs

palantir::release::package_rpm
