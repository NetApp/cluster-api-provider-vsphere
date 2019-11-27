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

package govmomi

import (
	"encoding/base64"

	"github.com/pkg/errors"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/context"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/services/govmomi/extra"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/services/govmomi/net"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/services/govmomi/tags"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/util"
)

// VMService provdes API to interact with the VMs using govmomi
type VMService struct{}

// ReconcileVM makes sure that the VM is in the desired state by:
//   1. Creating the VM if it does not exist, then...
//   2. Updating the VM with the bootstrap data, such as the cloud-init meta and user data, before...
//   3. Powering on the VM, and finally...
//   4. Returning the real-time state of the VM to the caller
func (vms *VMService) ReconcileVM(ctx *context.MachineContext) (infrav1.VirtualMachine, error) {

	// Create a VM object
	vm := infrav1.VirtualMachine{
		Name:  ctx.Machine.Name,
		State: infrav1.VirtualMachineStatePending,
	}

	// If there is an in-flight task associated with this VM then do not
	// reconcile the VM until the task is completed.
	if inFlight, err := reconcileInFlightTask(ctx); err != nil || inFlight {
		return vm, err
	}

	// Before going further, we need the VM's managed object reference.
	vmRef, err := findVM(ctx)
	if err != nil {
		if !isNotFound(err) {
			return vm, err
		}
		// If VM's MoRef could not be found then the VM does not exist,
		// and the VM should be created.
		return vm, createVM(ctx, []byte(*ctx.Machine.Spec.Bootstrap.Data))
	}

	//
	// At this point we know the VM exists, so it needs to be updated.
	//

	// Create a new virtualMachineContext to reconcile the VM.
	vmCtx := &virtualMachineContext{
		MachineContext: *ctx,
		Obj:            object.NewVirtualMachine(ctx.Session.Client.Client, vmRef),
		Ref:            vmRef,
		State:          &vm,
	}

	if err := vms.reconcileUUID(vmCtx); err != nil {
		return vm, err
	}

	if err := vms.reconcileNetworkStatus(vmCtx); err != nil {
		return vm, nil
	}

	if ok, err := vms.reconcileMetadata(vmCtx); err != nil || !ok {
		return vm, err
	}

	if ok, err := vms.reconcilePowerState(vmCtx); err != nil || !ok {
		return vm, err
	}

	// NetApp
	if err := vms.reconcileTags(ctx); err != nil {
		// Just log the error
		ctx.Logger.Error(err, "error reconciling tags")
	}

	vm.State = infrav1.VirtualMachineStateReady
	return vm, nil
}

// DestroyVM powers off and destroys a virtual machine.
func (vms *VMService) DestroyVM(ctx *context.MachineContext) (infrav1.VirtualMachine, error) {

	vm := infrav1.VirtualMachine{
		Name:  ctx.Machine.Name,
		State: infrav1.VirtualMachineStatePending,
	}

	// If there is an in-flight task associated with this VM then do not
	// reconcile the VM until the task is completed.
	if inFlight, err := reconcileInFlightTask(ctx); err != nil || inFlight {
		return vm, err
	}

	// Before going further, we need the VM's managed object reference.
	vmRef, err := findVM(ctx)
	if err != nil {
		// If the VM's MoRef could not be found then the VM no longer exists. This
		// is the desired state.
		if isNotFound(err) {
			vm.State = infrav1.VirtualMachineStateNotFound

			// NetApp
			if err := vms.deleteTags(ctx); err != nil {
				// Just log the error
				ctx.Logger.Error(err, "error deleting tags")
			}

			return vm, nil
		}
		return vm, err
	}

	//
	// At this point we know the VM exists, so it needs to be destroyed.
	//

	// Create a new virtualMachineContext to reconcile the VM.
	vmCtx := &virtualMachineContext{
		MachineContext: *ctx,
		Obj:            object.NewVirtualMachine(ctx.Session.Client.Client, vmRef),
		Ref:            vmRef,
		State:          &vm,
	}

	// Power off the VM.
	powerState, err := vms.getPowerState(vmCtx)
	if err != nil {
		return vm, err
	}
	if powerState == infrav1.VirtualMachinePowerStatePoweredOn {
		taskRef, err := vms.powerOffVM(vmCtx)
		if err != nil {
			return vm, err
		}
		ctx.VSphereMachine.Status.TaskRef = taskRef
		ctx.Logger.V(6).Info("reenqueue to wait for power off op")
		return vm, nil
	}

	// At this point the VM is not powered on and can be destroyed. Store the
	// destroy task's reference and return a requeue error.
	ctx.Logger.V(6).Info("destroying vm")
	taskRef, err := vms.destroyVM(vmCtx)
	if err != nil {
		return vm, err
	}
	ctx.VSphereMachine.Status.TaskRef = taskRef
	ctx.Logger.V(6).Info("reenqueue to wait for destroy op")
	return vm, nil
}

func (vms *VMService) reconcileNetworkStatus(ctx *virtualMachineContext) error {
	netStatus, err := vms.getNetworkStatus(ctx)
	if err != nil {
		return err
	}
	ctx.State.Network = netStatus
	return nil
}

func (vms *VMService) reconcileMetadata(ctx *virtualMachineContext) (bool, error) {
	existingMetadata, err := vms.getMetadata(ctx)
	if err != nil {
		return false, err
	}

	newMetadata, err := util.GetMachineMetadata(ctx.Machine.Name, *ctx.VSphereMachine, ctx.State.Network...)
	if err != nil {
		return false, err
	}

	// If the metadata is the same then return early.
	if string(newMetadata) == existingMetadata {
		return true, nil
	}

	ctx.Logger.V(4).Info("updating metadata")
	taskRef, err := vms.setMetadata(ctx, newMetadata)
	if err != nil {
		return false, errors.Wrapf(err, "unable to set metadata on vm %q", ctx)
	}

	ctx.VSphereMachine.Status.TaskRef = taskRef
	ctx.Logger.V(6).Info("reenqueue to track update metadata task")
	return false, nil
}

func (vms *VMService) reconcilePowerState(ctx *virtualMachineContext) (bool, error) {
	powerState, err := vms.getPowerState(ctx)
	if err != nil {
		return false, err
	}
	switch powerState {
	case infrav1.VirtualMachinePowerStatePoweredOff:
		ctx.Logger.V(4).Info("powering on")
		taskRef, err := vms.powerOnVM(ctx)
		if err != nil {
			return false, errors.Wrapf(err, "failed to trigger power on op for vm %q", ctx)
		}
		// update the tak ref to track
		ctx.VSphereMachine.Status.TaskRef = taskRef
		ctx.Logger.V(6).Info("reenqueue to wait for power on state")
		return false, nil
	case infrav1.VirtualMachinePowerStatePoweredOn:
		ctx.Logger.V(6).Info("powered on")
	default:
		return false, errors.Errorf("unexpected power state %q for vm %q", powerState, ctx)
	}

	return true, nil
}

func (vms *VMService) reconcileUUID(ctx *virtualMachineContext) error {
	ctx.State.BiosUUID = ctx.Obj.UUID(ctx)
	return nil
}

func (vms *VMService) getPowerState(ctx *virtualMachineContext) (infrav1.VirtualMachinePowerState, error) {
	powerState, err := ctx.Obj.PowerState(ctx)
	if err != nil {
		return "", err
	}

	switch powerState {
	case types.VirtualMachinePowerStatePoweredOn:
		return infrav1.VirtualMachinePowerStatePoweredOn, nil
	case types.VirtualMachinePowerStatePoweredOff:
		return infrav1.VirtualMachinePowerStatePoweredOff, nil
	case types.VirtualMachinePowerStateSuspended:
		return infrav1.VirtualMachinePowerStateSuspended, nil
	default:
		return "", errors.Errorf("unexpected power state %q for vm %q", powerState, ctx)
	}
}

func (vms *VMService) getMetadata(ctx *virtualMachineContext) (string, error) {
	var (
		obj mo.VirtualMachine

		pc    = property.DefaultCollector(ctx.Session.Client.Client)
		props = []string{"config.extraConfig"}
	)

	if err := pc.RetrieveOne(ctx, ctx.Ref, props, &obj); err != nil {
		return "", errors.Wrapf(err, "unable to fetch props %v for vm %v", props, ctx.Ref)
	}
	if obj.Config == nil {
		return "", nil
	}

	var metadataBase64 string
	for _, ec := range obj.Config.ExtraConfig {
		if optVal := ec.GetOptionValue(); optVal != nil {
			// TODO(akutz) Using a switch instead of if in case we ever
			//             want to check the metadata encoding as well.
			//             Since the image stamped images always use
			//             base64, it should be okay to not check.
			// nolint
			switch optVal.Key {
			case guestInfoKeyMetadata:
				if v, ok := optVal.Value.(string); ok {
					metadataBase64 = v
				}
			}
		}
	}

	if metadataBase64 == "" {
		return "", nil
	}

	metadataBuf, err := base64.StdEncoding.DecodeString(metadataBase64)
	if err != nil {
		return "", errors.Wrapf(err, "unable to decode metadata for %q", ctx)
	}

	return string(metadataBuf), nil
}

func (vms *VMService) setMetadata(ctx *virtualMachineContext, metadata []byte) (string, error) {
	var extraConfig extra.Config
	extraConfig.SetCloudInitMetadata(metadata)

	task, err := ctx.Obj.Reconfigure(ctx, types.VirtualMachineConfigSpec{
		ExtraConfig: extraConfig,
	})
	if err != nil {
		return "", errors.Wrapf(err, "unable to set metadata on vm %q", ctx)
	}

	return task.Reference().Value, nil
}

func (vms *VMService) getNetworkStatus(ctx *virtualMachineContext) ([]infrav1.NetworkStatus, error) {
	allNetStatus, err := net.GetNetworkStatus(ctx, ctx.Session.Client.Client, ctx.Ref)
	if err != nil {
		return nil, err
	}
	ctx.Logger.V(6).Info("got allNetStatus", "status", allNetStatus)
	apiNetStatus := []infrav1.NetworkStatus{}
	for _, s := range allNetStatus {
		apiNetStatus = append(apiNetStatus, infrav1.NetworkStatus{
			Connected:   s.Connected,
			IPAddrs:     sanitizeIPAddrs(&ctx.MachineContext, s.IPAddrs),
			MACAddr:     s.MACAddr,
			NetworkName: s.NetworkName,
		})
	}
	return apiNetStatus, nil
}

func (vms *VMService) powerOnVM(ctx *virtualMachineContext) (string, error) {
	task, err := ctx.Obj.PowerOn(ctx)
	if err != nil {
		return "", err
	}
	return task.Reference().Value, nil
}

func (vms *VMService) powerOffVM(ctx *virtualMachineContext) (string, error) {
	task, err := ctx.Obj.PowerOff(ctx)
	if err != nil {
		return "", err
	}
	return task.Reference().Value, nil
}

func (vms *VMService) destroyVM(ctx *virtualMachineContext) (string, error) {
	task, err := ctx.Obj.Destroy(ctx)
	if err != nil {
		return "", err
	}
	return task.Reference().Value, nil
}

// NetApp
func (vms *VMService) reconcileTags(ctx *context.MachineContext) error {
	vmRef, err := findVM(ctx)
	if err != nil {
		return err
	}
	err = tags.TagNKSMachine(ctx, vmRef)
	if err != nil {
		return err
	}
	return nil
}

// NetApp
func (vms *VMService) deleteTags(ctx *context.MachineContext) error {
	err := tags.CleanupNKSTags(ctx)
	if err != nil {
		return err
	}
	return nil
}
