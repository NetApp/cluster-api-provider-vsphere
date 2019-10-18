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
	"fmt"
	"github.com/NetApp/nks-on-prem-ipam/pkg/ipam"

	"github.com/pkg/errors"

	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/context"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/services/govmomi/extra"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/services/govmomi/net"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/services/govmomi/tags"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/util"
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
		Name:  ctx.VSphereMachine.Name,
		State: infrav1.VirtualMachineStatePending,
	}

	// If there is no pending task or no machine ref then no VM exits, create one
	if ctx.VSphereMachine.Status.TaskRef == "" && ctx.VSphereMachine.Spec.MachineRef == "" {
		ref, err := findVMByInstanceUUID(ctx)
		if err != nil {
			return vm, err
		}

		if ref != "" {
			return vm, errors.Errorf("vm with the same Instance UUID already exists %q", ctx.VSphereMachine.Name)
		}

		// no VM exits, goahead and create a VM
		if err := createVM(ctx, []byte(*ctx.Machine.Spec.Bootstrap.Data)); err != nil {
			return vm, err
		}

		return vm, nil
	}

	// The VM exists at this point, so let's address steps two through four
	// from this function's documented workflow (please see the function's
	// GoDoc comments for more information)

	// Check for in-flight tasks
	if inflight, err := hasInFlightTask(ctx); err != nil || inflight {
		return vm, err
	}

	// Update the MachineRef if not already present
	if ctx.VSphereMachine.Spec.MachineRef == "" {
		moRefID, err := findVMByInstanceUUID(ctx)
		if err != nil {
			return vm, err
		}
		if moRefID != "" {
			ctx.VSphereMachine.Spec.MachineRef = moRefID
			ctx.Logger.V(6).Info("discovered moref id", "moref-id", ctx.VSphereMachine.Spec.MachineRef)
		}
	}

	// Verify if the VM exists
	obj, err := getVMObject(ctx)
	if err != nil {
		// The name lookup fails, therefore the VM does not exist.
		ctx.VSphereMachine.Spec.MachineRef = ""
		return vm, err
	}

	if err := vms.reconcileNetworkStatus(ctx, &vm); err != nil {
		return vm, nil
	}

	// NetApp
	if ok, err := vms.reconcileIPAM(ctx, vm); err != nil || !ok {
		return vm, err
	}

	if ok, err := vms.reconcileMetadata(ctx, vm); err != nil || !ok {
		return vm, err
	}

	if ok, err := vms.reconcilePowerState(ctx); err != nil || !ok {
		return vm, err
	}

	if err := vms.reconcileUUIUDs(ctx, &vm, obj); err != nil {
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
		Name:  ctx.VSphereMachine.Name,
		State: infrav1.VirtualMachineStatePending,
	}

	if ctx.VSphereMachine.Spec.MachineRef == "" && ctx.VSphereMachine.Status.TaskRef == "" {
		// vm already deleted
		vm.State = infrav1.VirtualMachineStateNotFound
		return vm, nil
	}

	// check for in-flight tasks
	if inflight, err := hasInFlightTask(ctx); err != nil || inflight {
		return vm, err
	}

	// check if VM actually exists
	if ctx.VSphereMachine.Spec.MachineRef != "" {
		moRefID, err := findVMByInstanceUUID(ctx)
		if err != nil {
			return vm, err
		}
		if moRefID == "" {
			// No vm exists
			// remove the MachineRef and set the vm state to notfound
			ctx.VSphereMachine.Spec.MachineRef = ""
			vm.State = infrav1.VirtualMachineStateNotFound

			// NetApp
			if err := vms.deleteTags(ctx); err != nil {
				// Just log the error
				ctx.Logger.Error(err, "error deleting tags")
			}

			return vm, nil
		}
	}

	// VM actually exists
	// Power off the VM if needed
	powerState, err := vms.getPowerState(ctx)
	if err != nil {
		return vm, err
	}
	if powerState == infrav1.VirtualMachinePowerStatePoweredOn {
		task, err := vms.powerOffVM(ctx)
		if err != nil {
			return vm, err
		}
		ctx.VSphereMachine.Status.TaskRef = task
		// requeue for VM to be powered off
		ctx.Logger.V(6).Info("reenqueue to wait for power off op")
		return vm, nil
	}

	// At this point the VM is not powered on and can be destroyed. Store the
	// destroy task's reference and return a requeue error.
	ctx.Logger.V(6).Info("destroying vm")
	task, err := vms.destroyVM(ctx)
	if err != nil {
		return vm, err
	}
	ctx.VSphereMachine.Status.TaskRef = task

	// Requeue
	ctx.Logger.V(6).Info("reenqueue to wait for destroy op")
	return vm, nil
}

func (vms *VMService) reconcileNetworkStatus(ctx *context.MachineContext, vm *infrav1.VirtualMachine) error {
	netStatus, err := vms.getNetworkStatus(ctx)
	if err != nil {
		return err
	}

	vm.Network = netStatus
	return nil
}

func (vms *VMService) reconcileMetadata(ctx *context.MachineContext, vm infrav1.VirtualMachine) (bool, error) {
	existingMetadata, err := vms.getMetadata(ctx)
	if err != nil {
		return false, err
	}

	newMetadata, err := util.GetMachineMetadata(*ctx.VSphereMachine, vm.Network...)
	if err != nil {
		return false, err
	}

	// If the metadata is the same then return early.
	if string(newMetadata) == existingMetadata {
		return true, nil
	}

	ctx.Logger.V(4).Info("updating metadata")
	task, err := vms.setMetadata(ctx, newMetadata)
	if err != nil {
		return false, errors.Wrapf(err, "unable to set metadata on vm %q", ctx)
	}

	// update taskref
	ctx.VSphereMachine.Status.TaskRef = task
	ctx.Logger.V(6).Info("reenqueue to track update metadata task")
	return false, nil
}

func (vms *VMService) reconcilePowerState(ctx *context.MachineContext) (bool, error) {
	powerState, err := vms.getPowerState(ctx)
	if err != nil {
		return false, err
	}
	switch powerState {
	case infrav1.VirtualMachinePowerStatePoweredOff:
		ctx.Logger.V(4).Info("powering on")
		task, err := vms.powerOnVM(ctx)
		if err != nil {
			return false, errors.Wrapf(err, "failed to trigger power on op for vm %q", ctx)
		}
		// update the tak ref to track
		ctx.VSphereMachine.Status.TaskRef = task
		ctx.Logger.V(6).Info("reenqueue to wait for power on state")
		return false, nil
	case infrav1.VirtualMachinePowerStatePoweredOn:
		ctx.Logger.V(6).Info("powered on")
	default:
		return false, errors.Errorf("unexpected power state %q for vm %q", powerState, ctx)
	}

	return true, nil
}

func (vms *VMService) reconcileUUIUDs(ctx *context.MachineContext, vm *infrav1.VirtualMachine, obj mo.VirtualMachine) error {
	// Temporarily removing this. It is calling a panic (nil pointer reference).
	// we dont use this anywhere so ti should be fine.
	// vm.InstanceUUID = obj.Config.InstanceUuid

	biosUUID, err := vms.getBiosUUID(ctx)
	if err != nil {
		return err
	}
	vm.BiosUUID = biosUUID
	return nil
}

func (vms *VMService) getPowerState(ctx *context.MachineContext) (infrav1.VirtualMachinePowerState, error) {

	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	pState, err := vm.PowerState(ctx)
	if err != nil {
		return "", err
	}

	switch pState {
	case types.VirtualMachinePowerStatePoweredOn:
		return infrav1.VirtualMachinePowerStatePoweredOn, nil
	case types.VirtualMachinePowerStatePoweredOff:
		return infrav1.VirtualMachinePowerStatePoweredOff, nil
	case types.VirtualMachinePowerStateSuspended:
		return infrav1.VirtualMachinePowerStateSuspended, nil
	default:
		return "", errors.Errorf("unexpected power state %q for vm %q", pState, ctx)
	}
}

func (vms *VMService) getMetadata(ctx *context.MachineContext) (string, error) {
	var (
		obj mo.VirtualMachine

		moRef = *(getMoRef(ctx))
		pc    = property.DefaultCollector(ctx.Session.Client.Client)
		props = []string{"config.extraConfig"}
	)

	if err := pc.RetrieveOne(ctx, moRef, props, &obj); err != nil {
		return "", errors.Wrapf(err, "unable to fetch props %v for vm %v", props, moRef)
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

func (vms *VMService) setMetadata(ctx *context.MachineContext, metadata []byte) (string, error) {
	var extraConfig extra.Config
	extraConfig.SetCloudInitMetadata(metadata)

	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	task, err := vm.Reconfigure(ctx, types.VirtualMachineConfigSpec{
		ExtraConfig: extraConfig,
	})
	if err != nil {
		return "", errors.Wrapf(err, "unable to set metadata on vm %q", ctx)
	}

	return task.Reference().Value, nil
}

func (vms *VMService) getNetworkStatus(ctx *context.MachineContext) ([]infrav1.NetworkStatus, error) {
	allNetStatus, err := net.GetNetworkStatus(ctx, ctx.Session.Client.Client, *(getMoRef(ctx)))
	if err != nil {
		return nil, err
	}
	ctx.Logger.V(6).Info("got allNetStatus", "status", allNetStatus)
	apiNetStatus := []infrav1.NetworkStatus{}
	for _, s := range allNetStatus {
		apiNetStatus = append(apiNetStatus, infrav1.NetworkStatus{
			Connected:   s.Connected,
			IPAddrs:     sanitizeIPAddrs(ctx, s.IPAddrs),
			MACAddr:     s.MACAddr,
			NetworkName: s.NetworkName,
		})
	}
	return apiNetStatus, nil
}

func (vms *VMService) getBiosUUID(ctx *context.MachineContext) (string, error) {
	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	return vm.UUID(ctx), nil
}

func (vms *VMService) powerOnVM(ctx *context.MachineContext) (string, error) {
	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	task, err := vm.PowerOn(ctx)
	if err != nil {
		return "", err
	}

	return task.Reference().Value, nil
}

func (vms *VMService) powerOffVM(ctx *context.MachineContext) (string, error) {
	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	task, err := vm.PowerOff(ctx)
	if err != nil {
		return "", err
	}

	return task.Reference().Value, nil
}

func (vms *VMService) destroyVM(ctx *context.MachineContext) (string, error) {
	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return "", err
	}

	task, err := vm.Destroy(ctx)
	if err != nil {
		return "", err
	}

	return task.Reference().Value, nil
}

// NetApp
func (vms *VMService) reconcileTags(ctx *context.MachineContext) error {
	vm, err := getVMfromMachineRef(ctx)
	if err != nil {
		return err
	}
	err = tags.TagNKSMachine(ctx, vm)
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

func (vms *VMService) reconcileIPAM(ctx *context.MachineContext, vm infrav1.VirtualMachine) (bool, error) {

	if ctx.VSphereMachine == nil {
		ctx.Logger.V(4).Info("machine infrastructure missing")
		return false, nil
	}

	// Create a copy of the devices
	devices := make([]infrav1.NetworkDeviceSpec, len(ctx.VSphereMachine.Spec.Network.Devices))
	for i := range ctx.VSphereMachine.Spec.Network.Devices {
		ctx.VSphereMachine.Spec.Network.Devices[i].DeepCopyInto(&devices[i])
	}

	// Find all devices that should get a static IP
	staticDevicesWithoutIPs := make([]*infrav1.NetworkDeviceSpec, 0)
	for i, device := range devices {
		if !device.DHCP4 && !device.DHCP6 && len(device.IPAddrs) == 0 {
			staticDevicesWithoutIPs = append(staticDevicesWithoutIPs, &devices[i])
		}
	}

	// If no static devices need IPs then nothing to do
	if len(staticDevicesWithoutIPs) == 0 {
		return true, nil
	}

	// TODO(thorsteinnth) Should we be doing the ip<->mac linking?
	// If we do, then we need to add the MAC address to the device spec, making it static, so that on re-clone
	// the machine comes up with the same mac address - preserving the ip<->mac link in the IPAM provider
	// At that point, are we guaranteed that it will remain unique, and that we do not need some "MAC address management service"?
	// i.e. can we mix generated MACs and static MACs in the same environment.

	/*
		// Assign MAC addresses to the static devices
		// NOTE: These MAC addresses should have been generated for us at this point, since the VM has already been cloned.
		// We add the MAC addresses explicitly to the spec here, so that on eventual VM deletion from vSphere and re-clone,
		// the MAC addresses will stay the same.
		if len(vm.Network) != len(devices) {
			ctx.Logger.V(6).Info("reenqueue to wait for network status") // TODO Needed?
			return false, nil
		}
		for i := range devices {
			devices[i].MACAddr = vm.Network[i].MACAddr
		}*/

	//staticMacAddresses := macAddresses[0:len(staticDevicesWithoutIPs)]

	// Determine zone
	if ctx.VSphereCluster == nil {
		ctx.Logger.V(4).Info("cluster infrastructure missing")
		return false, nil
	}
	isManagementZone := ctx.VSphereCluster.Spec.CloudProviderConfiguration.Labels.Zone == util.ManagementZoneName

	// Determine network types for each device
	networkTypeDeviceMap := make(map[ipam.NetworkType][]*infrav1.NetworkDeviceSpec)
	for i := range staticDevicesWithoutIPs {
		networkType, err := util.GetNetworkType(*ctx.VSphereMachine, isManagementZone, staticDevicesWithoutIPs[i].NetworkName)
		if err != nil {
			return false, errors.Wrapf(err, "could not get network type")
		}
		networkTypeDeviceMap[networkType] = append(networkTypeDeviceMap[networkType], staticDevicesWithoutIPs[i])
	}

	agent, err := util.GetIPAMAgent(ctx.Logger, ctx.Client)
	if err != nil {
		return false, errors.Wrap(err, "could not get IPAM agent")
	}

	for networkType, networkTypeDevices := range networkTypeDeviceMap {
		// TODO Skipping the MAC address linking for now
		reservations, err := agent.ReserveIPs(networkType, ipam.IPv4, len(networkTypeDevices), nil)
		if err != nil {
			return false, errors.Wrapf(err, "could not reserve IPs for network type %q", string(networkType))
		}
		if err := assignReservationsToDevices(reservations, networkTypeDevices); err != nil {
			// Let's try to release the reservations
			ips := getReservationIPs(reservations)
			if err := agent.ReleaseIPs(networkType, ips); err != nil {
				ctx.Logger.Error(err, "failed to assign IP reservations, could not release IPs", "IPs", ips)
			}
			return false, errors.Wrap(err, "could not assign IP reservations to devices")
		}
		// Assign the modified devices
		ctx.VSphereMachine.Spec.Network.Devices = devices
		// Add annotation marking machine as IPAM managed
		ctx.VSphereMachine.Annotations[util.IPAMManagedAnnotationKey] = "true"
	}

	return true, nil
}

func assignReservationsToDevices(reservations []ipam.IPAddressReservation, devices []*infrav1.NetworkDeviceSpec) error {
	if len(reservations) != len(devices) {
		return fmt.Errorf("unexpected number of reservations %d, wanted %d", len(reservations), len(devices))
	}
	for i := range devices {
		reservation := reservations[i]
		devices[i].IPAddrs = append(devices[i].IPAddrs, reservation.Address)
		devices[i].Nameservers = reservation.NetworkConfig.NameServers
		devices[i].Gateway4 = reservation.NetworkConfig.DefaultGateway
		devices[i].SearchDomains = reservation.NetworkConfig.DomainSearch
	}
	return nil
}

func getReservationIPs(reservations []ipam.IPAddressReservation) []string {
	ips := make([]string, 0)
	for _, res := range reservations {
		ips = append(ips, res.Address)
	}
	return ips
}
