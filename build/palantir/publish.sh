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

set -eu -o pipefail
source "$(dirname $0)/script_functions.sh"

version=$(git_version)
if is_snapshot_version; then
    publish_repo=https://artifactory.palantir.build/artifactory/internal-dist-snapshot
else
    publish_repo=https://artifactory.palantir.build/artifactory/internal-dist-release
fi

release_tars_dir=$(dirname $0)/../../_output/release-tars

# Publish tarball to Artifactory.
server_tar_path=${release_tars_dir}/kubernetes-server-linux-amd64.tar.gz
palantir::publish::publish_product "$server_tar_path" "$publish_repo" com.palantir.rubix kubernetes-server "$version" tar.gz

# Publish rpm to Artifactory.
rpm_path=${release_tars_dir}/kubernetes-bin.rpm
palantir::publish::publish_product "$rpm_path" "$publish_repo" com.palantir.rubix kubernetes-bin "$version" rpm

# Publish to Docker
base_repo="docker.palantir.build/rubix"
transient_repo="sandbox.docker.palantir.build/rubix"
binary_dir="$(dirname $0)"/../../_output/dockerized/bin/linux/amd64
arch="amd64"
binaries=(
          kube-apiserver,busybox
          kube-controller-manager,busybox
          kube-scheduler,busybox
          kube-proxy,gcr.io/google_containers/debian-iptables-amd64:v5
        )

for wrappable in "${binaries[@]}"; do
    oldifs=$IFS
    IFS=","
    set $wrappable
    IFS=$oldifs

    binary_name="$1"
    base_image="$2"

    echo "Starting Docker build for image: ${binary_name}"

    docker_build_path="${binary_dir}/${binary_name}.dockerbuild"
    docker_file_path="${docker_build_path}/Dockerfile"
    binary_file_path="${binary_dir}/${binary_name}"

    if is_snapshot_version; then
        docker_image_tag="${transient_repo}/${binary_name}:${version}"
    else
        docker_image_tag="${base_repo}/${binary_name}:${version}"
    fi

    rm -rf ${docker_build_path}
    mkdir -p ${docker_build_path}
    ln ${binary_dir}/${binary_name} ${docker_build_path}/${binary_name}
    printf " FROM ${base_image} \n ADD ${binary_name} /usr/local/bin/${binary_name}\n" > ${docker_file_path}

    docker build --pull -t "${docker_image_tag}" ${docker_build_path}
    docker push $docker_image_tag

done
