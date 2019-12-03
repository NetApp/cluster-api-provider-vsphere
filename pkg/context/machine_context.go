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
	"fmt"

	"github.com/go-logr/logr"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha2"
	"sigs.k8s.io/cluster-api/util/patch"

	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/session"
)

// MachineContext is a Go context used with a CAPI cluster.
type MachineContext struct {
	*ClusterContext
	Machine        *clusterv1.Machine
	VSphereMachine *infrav1.VSphereMachine
	Session        *session.Session
	Logger         logr.Logger
	PatchHelper    *patch.Helper
}

// String returns ControllerManagerName/ControllerName/ClusterAPIVersion/ClusterNamespace/ClusterName/MachineName.
func (c *MachineContext) String() string {
	return fmt.Sprintf("%s/%s", c.ClusterContext.String(), c.VSphereMachine.Name)
}

// Patch updates the object and its status on the API server.
func (c *MachineContext) Patch() error {
	return c.PatchHelper.Patch(c, c.VSphereMachine)
}

// GetLogger returns this context's logger.
func (c *MachineContext) GetLogger() logr.Logger {
	return c.Logger
}

// GetSession returns this context's session.
func (c *MachineContext) GetSession() *session.Session {
	return c.Session
}

// NetApp
// GetNKSClusterInfo returns NKS information on the cluster that the machine is a part of
// Returns clusterID, workspaceID, isServiceCluster
func (c *MachineContext) GetNKSClusterInfo() (string, string, bool) {

	const ClusterIdLabel = "hci.nks.netapp.com/cluster"
	const WorkspaceIdLabel = "hci.nks.netapp.com/workspace"
	const ClusterRoleLabel = "hci.nks.netapp.com/role"
	const ServiceClusterRole = "service-cluster"

	var workspaceID = ""
	var clusterID = ""
	var isServiceCluster bool

	if val, ok := c.Cluster.Labels[WorkspaceIdLabel]; ok {
		workspaceID = val
	}
	if val, ok := c.Cluster.Labels[ClusterIdLabel]; ok {
		clusterID = val
	}
	if val, ok := c.Cluster.Labels[ClusterRoleLabel]; ok {
		if val == ServiceClusterRole {
			isServiceCluster = true
		}
	}

	return clusterID, workspaceID, isServiceCluster
}

// NetApp
func (c *MachineContext) GetMachineAnnotation() string {
	// TODO: At this point we do not know if it is a service cluster - need better communication of that
	clusterID, workspaceID, _ := c.GetNKSClusterInfo()
	return fmt.Sprintf("VM is part of NKS kubernetes cluster %s with cluster ID %s in workspace with ID %s", c.Cluster.Name, clusterID, workspaceID)
}
