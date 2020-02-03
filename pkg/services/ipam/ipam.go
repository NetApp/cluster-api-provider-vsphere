package ipam

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/NetApp/nks-on-prem-ipam/pkg/ipam"
	"github.com/NetApp/nks-on-prem-ipam/pkg/ipam/factory"
	"github.com/pkg/errors"
	apiv1 "k8s.io/api/core/v1"
	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	capvcontext "sigs.k8s.io/cluster-api-provider-vsphere/pkg/context"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	primaryNetworkNameAnnotationKey = "primary-network-name"
	storageNetworkNameAnnotationKey = "storage-network-name"

	ipamConfigNameAnnotationKey      = "ipam-config-secret-name"
	ipamConfigNamespaceAnnotationKey = "ipam-config-secret-namespace"
	ipamConfigKey                    = "config.json"

	WorkspaceIDMetaDataKey       = "hci.nks.netapp.com/workspace"
	ClusterIDMetaDataKey         = "hci.nks.netapp.com/cluster"
	ClusterInstanceIDMetaDataKey = "hci.nks.netapp.com/instanceid"
	VMNameMetaDataKey            = "hci.nks.netapp.com/vmname"
	IPReservationTypeMetaDataKey = "hci.nks.netapp.com/reservationtype"
	IPReservationTypeNodeIP      = "nodeip"

	zoneNameAnnotationKey    = "hci.nks.netapp.com/zone"
	ipamManagedAnnotationKey = "ipam-managed"

	managementZoneName = "management"
)

type Service struct{}

type ipamManagedAnnotation struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

// TODO Use metadata constants

func (svc *Service) ReconcileIPAM(ctx *capvcontext.MachineContext) error {

	if ctx.VSphereMachine == nil {
		return fmt.Errorf("machine infrastructure missing")
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
		return nil
	}

	networkTypeDeviceMap, err := getNetworkTypeDeviceMap(ctx, staticDevicesWithoutIPs)
	if err != nil {
		return errors.Wrap(err, "could not get network types for devices")
	}

	agent, err := getIPAMAgent(ctx)
	if err != nil {
		return errors.Wrap(err, "could not get ipam agent")
	}

	metaData := getReservationMetaData(ctx)

	for networkType, networkTypeDevices := range networkTypeDeviceMap {

		// TODO It is forbidden to have multiple devices on the same network
		// TODO That shouldn't be an option here - should error out if that happens
		var reservationNames []string
		for range networkTypeDevices {
			reservationName := getReservationName(ctx, networkType)
			reservationNames = append(reservationNames, reservationName)
		}

		reservations, err := agent.ReserveIPs(networkType, ipam.IPv4, len(networkTypeDevices), reservationNames, nil, metaData)
		if err != nil {
			return errors.Wrapf(err, "could not reserve IPs for network type %q", string(networkType))
		}
		ctx.Logger.Info("Reserved IPs", "networkType", string(networkType), "reservations", mapStateAnnotation(reservations))

		// Update IPAM managed annotation

		networkTypeToReservations := make(map[string][]ipamManagedAnnotation)
		val, ok := ctx.VSphereMachine.Annotations[ipamManagedAnnotationKey]
		if ok {
			if err := json.Unmarshal([]byte(val), &networkTypeToReservations); err != nil {
				cleanupReservations(ctx, agent, networkType, reservations)
				return errors.Wrap(err, "failed to unmarshal ipam state annotation")
			}
		}
		networkTypeReservations, ok := networkTypeToReservations[string(networkType)]
		if ok {
			networkTypeToReservations[string(networkType)] = append(networkTypeReservations, mapStateAnnotation(reservations)...)
		} else {
			networkTypeToReservations[string(networkType)] = mapStateAnnotation(reservations)
		}
		marshalled, err := json.Marshal(networkTypeToReservations)
		if err != nil {
			cleanupReservations(ctx, agent, networkType, reservations)
			return errors.Wrap(err, "failed to marshal ipam state annotation")
		}
		ctx.VSphereMachine.Annotations[ipamManagedAnnotationKey] = string(marshalled)

		// Assign to devices

		if err := assignReservationsToDevices(reservations, networkTypeDevices); err != nil {
			cleanupReservations(ctx, agent, networkType, reservations)
			ctx.VSphereMachine.Annotations[ipamManagedAnnotationKey] = val // Revert annotation
			return errors.Wrap(err, "could not assign IP reservations to devices")
		}
		// Assign the modified devices
		ctx.VSphereMachine.Spec.Network.Devices = devices
	}

	return nil
}

// ReleaseIPAM releases the IP addresses specified in the ipam-managed annotation on the VSphereMachine
func (svc *Service) ReleaseIPAM(ctx *capvcontext.MachineContext) error {

	if ctx.VSphereMachine == nil {
		return fmt.Errorf("machine infrastructure missing")
	}

	// If this machine is not IPAM managed we can bail early
	val, ok := ctx.VSphereMachine.Annotations[ipamManagedAnnotationKey]
	if !ok {
		return nil
	}

	networkTypeToReservations := make(map[string][]ipamManagedAnnotation)
	if err := json.Unmarshal([]byte(val), &networkTypeToReservations); err != nil {
		return errors.Wrap(err, "failed to unmarshal ipam state annotation")
	}

	if len(networkTypeToReservations) == 0 {
		// Nothing to do
		return nil
	}

	agent, err := getIPAMAgent(ctx)
	if err != nil {
		return errors.Wrap(err, "could not get ipam agent")
	}

	for netType, reservations := range networkTypeToReservations {
		networkType, err := mapNetworkType(netType)
		if err != nil {
			return errors.Wrapf(err, "could not map network type")
		}
		if len(reservations) > 0 {
			reservationIDs := make([]string, 0, len(reservations))
			for _, res := range reservations {
				reservationIDs = append(reservationIDs, res.ID)
			}
			if err := agent.ReleaseIPs(networkType, reservationIDs); err != nil {
				return errors.Wrapf(err, "could not release IPs: %s", reservationIDs)
			}
			ctx.Logger.Info("Released IPs", "networkType", string(networkType), "IDs", reservationIDs)
		}
		delete(networkTypeToReservations, netType)
		marshalled, err := json.Marshal(networkTypeToReservations)
		if err != nil {
			return errors.Wrap(err, "failed to marshal ipam state annotation")
		}
		ctx.VSphereMachine.Annotations[ipamManagedAnnotationKey] = string(marshalled)
	}

	return nil
}

func cleanupReservations(ctx *capvcontext.MachineContext, agent ipam.Agent, networkType ipam.NetworkType, reservations []ipam.IPAddressReservation) {
	ids := getReservationIDs(reservations)
	ctx.Logger.Info("Cleaning up IP reservations", "networkType", string(networkType), "IDs", ids)
	if err := agent.ReleaseIPs(networkType, ids); err != nil {
		ctx.Logger.Error(err, "failed to clean up reservations, could not release IPs", "IDs", ids)
	}
}

func getNetworkType(machine infrav1.VSphereMachine, managementZone bool, networkName string) (ipam.NetworkType, error) {

	primaryNetworkName, ok := machine.Annotations[primaryNetworkNameAnnotationKey]
	if !ok {
		return "", fmt.Errorf("primary network name annotation missing")
	}
	if networkName == primaryNetworkName {
		if managementZone {
			return ipam.Management, nil
		}
		return ipam.Workload, nil
	}

	storageNetworkName, ok := machine.Annotations[storageNetworkNameAnnotationKey]
	// Storage network is not necessarily present
	if ok && networkName == storageNetworkName {
		return ipam.Data, nil
	}

	return "", fmt.Errorf("unknown network type for network %q", networkName)
}

func mapNetworkType(networkType string) (ipam.NetworkType, error) {
	if networkType == string(ipam.Management) {
		return ipam.Management, nil
	}
	if networkType == string(ipam.Workload) {
		return ipam.Workload, nil
	}
	if networkType == string(ipam.Data) {
		return ipam.Data, nil
	}
	return ipam.Workload, fmt.Errorf("unknown network type %q", networkType)
}

func getNetworkTypeDeviceMap(ctx *capvcontext.MachineContext, devices []*infrav1.NetworkDeviceSpec) (map[ipam.NetworkType][]*infrav1.NetworkDeviceSpec, error) {

	// Determine zone
	zoneName, ok := ctx.VSphereMachine.Annotations[zoneNameAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("zone missing from machine")
	}
	isManagementZone := zoneName == managementZoneName

	// Determine network types for each device
	networkTypeDeviceMap := make(map[ipam.NetworkType][]*infrav1.NetworkDeviceSpec)
	for i := range devices {
		networkType, err := getNetworkType(*ctx.VSphereMachine, isManagementZone, devices[i].NetworkName)
		if err != nil {
			return nil, errors.Wrapf(err, "could not get network type")
		}
		networkTypeDeviceMap[networkType] = append(networkTypeDeviceMap[networkType], devices[i])
	}

	return networkTypeDeviceMap, nil
}

func assignReservationsToDevices(reservations []ipam.IPAddressReservation, devices []*infrav1.NetworkDeviceSpec) error {
	if len(reservations) != len(devices) {
		return fmt.Errorf("unexpected number of reservations %d, wanted %d", len(reservations), len(devices))
	}
	for i, device := range devices {
		reservation := reservations[i]
		prefixLengthSuffix := "/" + strconv.Itoa(reservation.NetworkConfig.PrefixLength)
		device.IPAddrs = append(device.IPAddrs, reservation.Address+prefixLengthSuffix)
		device.Nameservers = reservation.NetworkConfig.NameServers
		device.Gateway4 = reservation.NetworkConfig.DefaultGateway
		device.SearchDomains = reservation.NetworkConfig.SearchDomains
	}
	return nil
}

func getReservationIDs(reservations []ipam.IPAddressReservation) []string {
	ids := make([]string, 0)
	for _, res := range reservations {
		ids = append(ids, res.ID)
	}
	return ids
}

func mapStateAnnotation(reservations []ipam.IPAddressReservation) []ipamManagedAnnotation {
	annotations := make([]ipamManagedAnnotation, 0)
	for _, res := range reservations {
		annotations = append(annotations, ipamManagedAnnotation{
			ID: res.ID,
			IP: res.Address,
		})
	}
	return annotations
}

func getIPAMAgent(ctx *capvcontext.MachineContext) (ipam.Agent, error) {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get ipam config")
	}
	agent, err := factory.GetAgent(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not get ipam agent")
	}
	// TODO This health check is way to slow on infoblox to do it this often I think
	if err := agent.HealthCheck(); err != nil {
		return nil, errors.Wrap(err, "ipam agent health check failed")
	}
	return agent, nil
}

func loadConfig(ctx *capvcontext.MachineContext) (*ipam.Config, error) {

	if ctx.Cluster == nil {
		return nil, fmt.Errorf("cluster context is nil")
	}

	secretName, ok := ctx.Cluster.Annotations[ipamConfigNameAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("ipam config secret name annotation missing")
	}
	secretNamespace, ok := ctx.Cluster.Annotations[ipamConfigNamespaceAnnotationKey]
	if !ok {
		return nil, fmt.Errorf("ipam config secret namespace annotation missing")
	}

	ctx.Logger.V(4).Info("Fetching IPAM configuration from secret", "secret-namespace", secretNamespace, "secret-name", secretName)

	ipamSecret := &apiv1.Secret{}
	ipamSecretKey := client.ObjectKey{
		Namespace: secretNamespace,
		Name:      secretName,
	}
	if err := ctx.Client.Get(context.TODO(), ipamSecretKey, ipamSecret); err != nil {
		return nil, errors.Wrapf(err, "error getting ipam config secret %s in namespace %s", secretName, secretNamespace)
	}

	configBytes, ok := ipamSecret.Data[ipamConfigKey]
	if !ok {
		return nil, fmt.Errorf("ipam config missing from secret %s in namespace %s", secretName, secretNamespace)
	}

	cfg := &ipam.Config{}
	err := json.Unmarshal(configBytes, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not unmarshal ipam config")
	}

	return cfg, nil
}

func getReservationMetaData(ctx *capvcontext.MachineContext) map[string]string {

	clusterID, workspaceID, _, _ := ctx.GetNKSClusterInfo()

	return map[string]string{
		IPReservationTypeMetaDataKey: IPReservationTypeNodeIP,
		ClusterIDMetaDataKey:         clusterID,
		WorkspaceIDMetaDataKey:       workspaceID,
		ClusterInstanceIDMetaDataKey: ctx.Cluster.Name,
		VMNameMetaDataKey:            ctx.Machine.Name,
	}
}

func getReservationName(ctx *capvcontext.MachineContext, networkType ipam.NetworkType) string {
	// If this is a reservation for the management or workload networks (primary networks)
	// then the reservation name should be the host name
	if networkType == ipam.Management || networkType == ipam.Workload {
		return ctx.Name
	}
	// If this is a secondary network (e.g. the data network) then we append the network type to the name
	return fmt.Sprintf("%s-%s", ctx.Name, networkType)
}
