/*
Copyright 2019 The Kubernetes Authors.

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

package context

import (
	"context"
	"fmt"

	apiv1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha2"
	"sigs.k8s.io/cluster-api/util/patch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/constants"
)

// ClusterContext is a Go context used with a CAPI cluster.
type ClusterContext struct {
	*ControllerContext
	Cluster        *clusterv1.Cluster
	VSphereCluster *v1alpha2.VSphereCluster
	PatchHelper    *patch.Helper
	Logger         logr.Logger
}

// String returns ClusterGroupVersionKind ClusterNamespace/ClusterName.
func (c *ClusterContext) String() string {
	return fmt.Sprintf("%s %s/%s", c.VSphereCluster.GroupVersionKind(), c.VSphereCluster.Namespace, c.VSphereCluster.Name)
}

// Patch updates the object and its status on the API server.
func (c *ClusterContext) Patch() error {
	return c.PatchHelper.Patch(c, c.VSphereCluster)
}

// NetApp
func GetVSphereCredentials(logger logr.Logger, c client.Client, cluster *clusterv1.Cluster) (string, string, error) {

	const credentialsNameAnnotationKey = "cluster-api-vsphere-credentials-secret-name"
	secretName, ok := cluster.Annotations[credentialsNameAnnotationKey]
	if !ok {
		return "", "", fmt.Errorf("vSphere credential secret name annotation missing")
	}
	if secretName == "" {
		return "", "", fmt.Errorf("vSphere credential secret name missing")
	}

	secretNamespace := cluster.ObjectMeta.Namespace

	logger.V(4).Info("Fetching vSphere credentials from secret", "secret-namespace", secretNamespace, "secret-name", secretName)

	credentialSecret := &apiv1.Secret{}
	credentialSecretKey := client.ObjectKey{
		Namespace: secretNamespace,
		Name:      secretName,
	}
	if err := c.Get(context.TODO(), credentialSecretKey, credentialSecret); err != nil {
		return "", "", errors.Wrapf(err, "error getting credentials secret %s in namespace %s", secretName, secretNamespace)
	}

	userBuf, userOk := credentialSecret.Data[constants.VSphereCredentialSecretUserKey]
	passBuf, passOk := credentialSecret.Data[constants.VSphereCredentialSecretPassKey]
	if !userOk || !passOk {
		return "", "", fmt.Errorf("improperly formatted credentials secret %q in namespace %s", secretName, secretNamespace)
	}
	username, password := string(userBuf), string(passBuf)

	logger.V(4).Info("Found vSphere credentials in secret", "secret-namespace", secretNamespace, "secret-name", secretName)

	return username, password, nil
}
