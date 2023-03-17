/*
Copyright 2019 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This file is forked from github.com/GoogleCloudPlatform/metacontroller.

package framework

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"

	"github.com/google/uuid"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

var apiserverURL = ""
var apiserverToken = ""
var apiserverDataDir = ""

const installApiserver = `
Cannot find kube-apiserver, cannot run integration tests

Please download kube-apiserver and ensure it is somewhere in the PATH.
See tools/get-kube-binaries.sh

`

// getApiserverPath returns a path to a kube-apiserver executable.
func getApiserverPath() (string, error) {
	return exec.LookPath("kube-apiserver")
}

// startApiserver executes a kube-apiserver instance.
// The returned function will signal the process and wait for it to exit.
func startApiserver() (func(), error) {
	apiserverPath, err := getApiserverPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, installApiserver)
		return nil, fmt.Errorf("could not find kube-apiserver in PATH: %v", err)
	}
	apiserverPort, err := getAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("could not get a port: %v", err)
	}
	apiserverURL = fmt.Sprintf("http://127.0.0.1:%d", apiserverPort)
	klog.Infof("starting kube-apiserver on %s", apiserverURL)

	apiserverDataDirLocal, err := ioutil.TempDir(os.TempDir(), "integration_test_apiserver_data")
	if err != nil {
		return nil, fmt.Errorf("unable to make temp kube-apiserver data dir: %v", err)
	}
	apiserverDataDir = apiserverDataDirLocal
	klog.Infof("storing kube-apiserver data in: %v", apiserverDataDir)

	apiserverToken = uuid.New().String()
	os.WriteFile(fmt.Sprintf("%s/token.csv", apiserverDataDir), []byte(fmt.Sprintf("%s,integration,1", apiserverToken)), 0644)

	abacRule1 := "{\"apiVersion\": \"abac.authorization.kubernetes.io/v1beta1\", \"kind\": \"Policy\", \"spec\": {\"user\": \"integration\", \"nonResourcePath\": \"*\"}}"
	abacRule2 := "{\"apiVersion\": \"abac.authorization.kubernetes.io/v1beta1\", \"kind\": \"Policy\", \"spec\": {\"user\": \"integration\", \"namespace\": \"*\", \"resource\": \"*\", \"apiGroup\": \"*\"}}"

	os.WriteFile(fmt.Sprintf("%s/abac", apiserverDataDir), []byte(fmt.Sprintf("%s\n%s", abacRule1, abacRule2)), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(
		ctx,
		apiserverPath,
		"--cert-dir", apiserverDataDir,
		"--secure-port", strconv.Itoa(apiserverPort),
		"--etcd-servers", etcdURL,
		"--service-account-signing-key-file", fmt.Sprintf("%s/apiserver.key", apiserverDataDir),
		"--service-account-key-file", fmt.Sprintf("%s/apiserver.key", apiserverDataDir),
		"--service-account-issuer", "kube-apiserver",
		"--authorization-mode", "ABAC",
		"--authorization-policy-file", fmt.Sprintf("%s/abac", apiserverDataDir),
		"--token-auth-file", fmt.Sprintf("%s/token.csv", apiserverDataDir),
	)

	// Uncomment these to see kube-apiserver output in test logs.
	// For operator tests, we generally don't expect problems at this level.
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr

	stop := func() {
		cancel()
		err := cmd.Wait()
		klog.Infof("kube-apiserver exit status: %v", err)
		err = os.RemoveAll(apiserverDataDir)
		if err != nil {
			klog.Warningf("error during kube-apiserver cleanup: %v", err)
		}
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to run kube-apiserver: %v", err)
	}
	return stop, nil
}

// ApiserverURL returns the URL of the kube-apiserver instance started by TestMain.
func ApiserverURL() string {
	return apiserverURL
}

// ApiserverConfig returns a rest.Config to connect to the test instance.
func ApiserverConfig() *rest.Config {
	return &rest.Config{
		Host: ApiserverURL(),
		BearerToken: apiserverToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}
}

func ApiserverToken() string {
	return apiserverToken
}

func ApiserverCrt() string {
	return fmt.Sprintf("%s/apiserver.crt", apiserverDataDir)
}
