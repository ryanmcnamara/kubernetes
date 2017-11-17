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

# This file replaces functions in build/lib/release.sh in order to limit the
# target platforms for kube::release::package_server_tarballs(). Without this,
# the build script would try to package tarballs for all architectures,
# including those no longer being built.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..

# Overrides kube::release::package_tarballs() to call palantir::release::package_server_tarballs()
# instead of kube::release::package_server_tarballs

function palantir::release::package_tarballs() {
  # Clean out any old releases
  rm -rf "${RELEASE_TARS}"
  rm -rf "${RELEASE_IMAGES}"
  mkdir -p "${RELEASE_TARS}"
  mkdir -p "${RELEASE_IMAGES}"
  kube::release::package_src_tarball &
  kube::release::package_client_tarballs &
  palantir::release::package_server_tarballs &
  kube::release::package_salt_tarball &
  kube::release::package_kube_manifests_tarball &
  kube::util::wait-for-jobs || { kube::log::error "previous tarball phase failed"; return 1; }

  kube::release::package_final_tarball & # _final depends on some of the previous phases
  kube::util::wait-for-jobs || { kube::log::error "previous tarball phase failed"; return 1; }
}


# Overrides kube::release::package_server_tarballs to limit platforms to only $target_platforms
# declared in build/palantir/targets.sh

function palantir::release::package_server_tarballs() {
  local platform
  for platform in "${target_platforms[@]}"; do
    local platform_tag=${platform/\//-} # Replace a "/" for a "-"
    local arch=$(basename ${platform})
    kube::log::status "Building tarball: server $platform_tag"

    local release_stage="${RELEASE_STAGE}/server/${platform_tag}/kubernetes"
    rm -rf "${release_stage}"
    mkdir -p "${release_stage}/server/bin"
    mkdir -p "${release_stage}/addons"

    # This fancy expression will expand to prepend a path
    # (${LOCAL_OUTPUT_BINPATH}/${platform}/) to every item in the
    # KUBE_SERVER_BINARIES array.
    cp "${KUBE_SERVER_BINARIES[@]/#/${LOCAL_OUTPUT_BINPATH}/${platform}/}" \
      "${release_stage}/server/bin/"

    kube::release::create_docker_images_for_server "${release_stage}/server/bin" "${arch}"

    # Include the client binaries here too as they are useful debugging tools.
    local client_bins=("${KUBE_CLIENT_BINARIES[@]}")
    if [[ "${platform%/*}" == "windows" ]]; then
      client_bins=("${KUBE_CLIENT_BINARIES_WIN[@]}")
    fi
    cp "${client_bins[@]/#/${LOCAL_OUTPUT_BINPATH}/${platform}/}" \
      "${release_stage}/server/bin/"

    cp "${KUBE_ROOT}/Godeps/LICENSES" "${release_stage}/"

    cp "${RELEASE_TARS}/kubernetes-src.tar.gz" "${release_stage}/"

    kube::release::clean_cruft

    local package_name="${RELEASE_TARS}/kubernetes-server-${platform_tag}.tar.gz"
    kube::release::create_tarball "${package_name}" "${release_stage}/.."
  done
}
