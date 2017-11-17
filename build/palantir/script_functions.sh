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

# Echoes the version string, which is the result of
# `git describe --tags` with the first 'v' removed
# If there are any uncommitted changes in the repository,
# ".dirty" is appended to the version. If the script is
# not run in a Git repository, exits the script.
function git_version() {
  local version=$(git describe --tags | sed 's/^v//')

  if [ -z "$version" ]; then
      echo "Unable to determine version using git describe --tags"
      exit 1
  fi

  if [ -n "$(git status --porcelain)" ]; then
      version="${version}.dirty"
  fi

  echo "$version"
}

# returns 0 if current version is a snapshot version (contains
# a git-describe-style sha1); returns 1 otherwise.
function is_snapshot_version() {
    [[ $(git_version) =~ [-+]g[0-9a-f]+ ]]
}

function palantir::publish::upload_file()
(
    set -euxo pipefail
    upload_filepath=$1
    upload_url=$2

    if [ ! -f "$upload_filepath" ]; then
        exit_with_message "Artifact not found at $upload_filepath"
    fi

    echo "Publishing $(basename $upload_filepath)"

    upload_md5=$(openssl md5 "$upload_filepath" | sed 's/.* //')
    upload_sha1=$(openssl sha1 "$upload_filepath" | sed 's/.* //')

    curl -XPUT -L -v --fail                               \
         -H "X-Checksum-Md5: $upload_md5"                 \
         -H "X-Checksum-Sha1: $upload_sha1"               \
         -u "$ARTIFACTORY_USERNAME:$ARTIFACTORY_PASSWORD" \
         --data-binary @"${upload_filepath}"              \
         "${upload_url}"

    # curl output does not end in newline, so call echo to
    # add a newline so that next output is on its own line
    echo ""
)

function palantir::publish::publish_product()
(
    set -euxo pipefail
    pub_filepath=$1
    pub_repository=$2
    pub_group=$3
    pub_product=$4
    pub_version=$5
    pub_packaging=$6

    pub_filename=${pub_product}-${pub_version}.${pub_packaging}
    pub_url=${pub_repository}/${pub_group//.//}/${pub_product}/${pub_version}/${pub_filename}

    pub_pompath=$(mktemp -d)/${pub_product}-${pub_version}.pom
    pub_pomurl=$(dirname ${pub_url})/$(basename ${pub_pompath})

    # cleanup temporary directory
    trap "rm -rf $(dirname ${pub_pompath})" EXIT

    cat > $pub_pompath <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${pub_group}</groupId>
  <artifactId>${pub_product}</artifactId>
  <version>${pub_version}</version>
  <packaging>${pub_packaging}</packaging>
</project>
EOF

    palantir::publish::upload_file "$pub_filepath" "$pub_url"
    palantir::publish::upload_file "$pub_pompath" "$pub_pomurl"
)
