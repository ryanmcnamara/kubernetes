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
	"time"
)

const (
	defaultRetryBackoff = time.Duration(500) * time.Millisecond
	minRetryBackoff     = time.Duration(1)
	maxRetryBackoff     = time.Duration(5) * time.Minute
)

type AdmissionConfig struct {
	Webhook webhookConfig `json:"webhook"`
}

type webhookConfig struct {
	KubeConfigFile  string   `json:"kubeConfigFile"`
	RetryBackoff    string   `json:"retryBackoff"`
	WhitelistImages []string `json:"whitelistImages"`
}

func (w *webhookConfig) RetryBackoffDuration() (time.Duration, error) {
	if w.RetryBackoff == "" {
		return defaultRetryBackoff, nil
	}
	dur, err := time.ParseDuration(w.RetryBackoff)
	if err != nil {
		return time.Duration(0), err
	}
	if dur > maxRetryBackoff {
		return maxRetryBackoff, nil
	}
	if dur < minRetryBackoff {
		return minRetryBackoff, nil
	}
	return dur, nil
}

