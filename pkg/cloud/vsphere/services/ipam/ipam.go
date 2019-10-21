package ipam

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/NetApp/nks-on-prem-ipam/pkg/ipam"
	"github.com/NetApp/nks-on-prem-ipam/pkg/ipam/mnode"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apiv1 "k8s.io/api/core/v1"
	infrav1 "sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	capvcontext "sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/context"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	dhcp           provider = "DHCP"
	mNodeIPService provider = "MNodeIPService"
	infoblox       provider = "Infoblox"

	primaryNetworkNameAnnotationKey = "primary-network-name"
	storageNetworkNameAnnotationKey = "storage-network-name"

	ManagementZoneName       = "management"
	IPAMManagedAnnotationKey = "ipam-managed"
)

type provider string

type ipamConfig struct {
	Provider    string `json:"provider,omitempty"`
	MNodeConfig *mNodeConfig
}

type mNodeConfig struct {
	Provider    string `json:"provider,omitempty"`
	IP          string `json:"ip,omitempty"`
	AuthHostURL string `json:"authHostURL,omitempty"`
	AuthSecret  string `json:"authSecret,omitempty"`
}

type IPAMService struct{}

func (svc *IPAMService) ReconcileIPAM(ctx *capvcontext.MachineContext) (bool, error) {

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

	networkTypeDeviceMap, err := getNetworkTypeDeviceMap(ctx, staticDevicesWithoutIPs)
	if err != nil {
		return false, errors.Wrap(err, "could not get network types for devices")
	}

	agent, err := getIPAMAgent(ctx.Logger, ctx.Client)
	if err != nil {
		return false, errors.Wrap(err, "could not get IPAM agent")
	}

	for networkType, networkTypeDevices := range networkTypeDeviceMap {
		// TODO Skipping the MAC address linking for now
		reservations, err := agent.ReserveIPs(networkType, ipam.IPv4, len(networkTypeDevices), nil)
		if err != nil {
			return false, errors.Wrapf(err, "could not reserve IPs for network type %q", string(networkType))
		}
		ctx.Logger.Info("Reserved IPs for network type %s: %s", string(networkType), reservations)
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
		ctx.VSphereMachine.Annotations[IPAMManagedAnnotationKey] = "true"
	}

	return true, nil
}

func (svc *IPAMService) ReleaseIPAM(ctx *capvcontext.MachineContext) (bool, error) {

	if ctx.VSphereMachine == nil {
		ctx.Logger.V(4).Info("machine infrastructure missing")
		return false, nil
	}

	// If this machine is not IPAM managed we can bail early
	ipamManaged, ok := ctx.VSphereMachine.Annotations[IPAMManagedAnnotationKey]
	if !ok || ipamManaged != "true" {
		return true, nil
	}

	// Create a copy of the devices
	devices := make([]infrav1.NetworkDeviceSpec, len(ctx.VSphereMachine.Spec.Network.Devices))
	for i := range ctx.VSphereMachine.Spec.Network.Devices {
		ctx.VSphereMachine.Spec.Network.Devices[i].DeepCopyInto(&devices[i])
	}

	// Find all devices that should have their IPs released
	staticDevicesWithIPs := make([]*infrav1.NetworkDeviceSpec, 0)
	for i, device := range devices {
		if !device.DHCP4 && !device.DHCP6 && len(device.IPAddrs) > 0 {
			staticDevicesWithIPs = append(staticDevicesWithIPs, &devices[i])
		}
	}

	// If no static devices with IPs then nothing to do
	if len(staticDevicesWithIPs) == 0 {
		return true, nil
	}

	networkTypeDeviceMap, err := getNetworkTypeDeviceMap(ctx, staticDevicesWithIPs)
	if err != nil {
		return false, errors.Wrap(err, "could not get network types for devices")
	}

	agent, err := getIPAMAgent(ctx.Logger, ctx.Client)
	if err != nil {
		return false, errors.Wrap(err, "could not get IPAM agent")
	}

	// TODO Should I fish the IPs from the devices, or be more explicit with annotations?
	// I need to mark the addresses as deleted I think - otherwise if I fail along the way I will try to delete them all,
	// also those that were previously deleted already - not idempotent
	for networkType, networkTypeDevices := range networkTypeDeviceMap {
		ips := make([]string, 0)
		for i := range networkTypeDevices {
			ips = append(ips, networkTypeDevices[i].IPAddrs...)
		}
		if len(ips) > 0 {
			err := agent.ReleaseIPs(networkType, ips)
			if err != nil {
				return false, errors.Wrap(err, "could not release IPs")
			}
			ctx.Logger.Info("Released IPs for network type %s: %s", string(networkType), ips)
		}
	}

	return true, nil
}

func getNetworkType(machine infrav1.VSphereMachine, managementZone bool, networkName string) (ipam.NetworkType, error) {
	primaryNetworkName, ok := machine.Annotations[primaryNetworkNameAnnotationKey]
	if !ok {
		return ipam.Workload, fmt.Errorf("primary network name annotation missing")

	}
	storageNetworkName, ok := machine.Annotations[storageNetworkNameAnnotationKey]
	if !ok {
		return ipam.Workload, fmt.Errorf("storage network name annotation missing")

	}
	if networkName == primaryNetworkName {
		if managementZone {
			return ipam.Management, nil
		}
		return ipam.Workload, nil
	}
	if networkName == storageNetworkName {
		return ipam.Data, nil
	}
	return ipam.Workload, fmt.Errorf("unknown network type for network %q", networkName)
}

func getIPAMAgent(logger logr.Logger, c client.Client) (ipam.Agent, error) {

	cfg, err := getIPAMConfiguration(logger, c)
	if err != nil {
		return nil, errors.Wrap(err, "could not get IPAM config")
	}

	if cfg.Provider == string(dhcp) {
		return nil, fmt.Errorf("cannot get IPAM agent for provider %s", cfg.Provider)
	}

	if cfg.Provider == string(infoblox) {
		// TODO Implement
		return nil, fmt.Errorf("cannot get IPAM agent for provider %s", cfg.Provider)
	}

	if cfg.Provider == string(mNodeIPService) {
		return getMNodeIPAMAgent(cfg.MNodeConfig)
	}

	return nil, fmt.Errorf("unknown IPAM provider %s", cfg.Provider)
}

func getMNodeIPAMAgent(cfg *mNodeConfig) (mnode.IPAMAgent, error) {

	const basePath = "ip/v1" // TODO(thorsteinnth): This should be configurable
	agent, err := mnode.NewIPAMAgent(
		cfg.IP,
		basePath,
		cfg.AuthHostURL,
		cfg.AuthSecret,
		true)
	if err != nil {
		return nil, fmt.Errorf("could not create mNode IPAM agent, %v", err)
	}

	if err := agent.HealthCheck(); err != nil {
		return nil, fmt.Errorf("mNode IPAM agent health check failed: %v", err)
	}

	return agent, nil
}

func getIPAMConfiguration(logger logr.Logger, c client.Client) (*ipamConfig, error) {

	// TODO Have it in each cluster's namespace? Or at least configurable through annotations
	const secretNamespace = "nks-system"
	const secretName = "ipam-config"
	const key = "config.json"

	logger.V(4).Info("Fetching IPAM configuration from secret", "secret-namespace", secretNamespace, "secret-name", secretName)

	ipamSecret := &apiv1.Secret{}
	ipamSecretKey := client.ObjectKey{
		Namespace: secretNamespace,
		Name:      secretName,
	}
	if err := c.Get(context.TODO(), ipamSecretKey, ipamSecret); err != nil {
		return nil, errors.Wrapf(err, "error getting IPAM config secret %s in namespace %s", secretName, secretNamespace)
	}

	configBytes, ok := ipamSecret.Data[key]
	if !ok {
		return nil, fmt.Errorf("IPAM config missing from secret %s in namespace %s", secretName, secretNamespace)
	}

	cfg := &ipamConfig{}
	err := json.Unmarshal(configBytes, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal IPAM config, %v", err)
	}

	switch cfg.Provider {
	case string(dhcp):
		return cfg, nil
	case string(infoblox):
		return cfg, nil
	case string(mNodeIPService):
		mNodeCfg := &mNodeConfig{}
		if err := json.Unmarshal(configBytes, mNodeCfg); err != nil {
			return nil, fmt.Errorf("could not unmarshal mNode IPAM config, %v", err)
		}
		cfg.MNodeConfig = mNodeCfg
		return cfg, nil
	default:
		return nil, fmt.Errorf("unknown IPAM provider %q", cfg.Provider)
	}
}

func getNetworkTypeDeviceMap(ctx *capvcontext.MachineContext, devices []*infrav1.NetworkDeviceSpec) (map[ipam.NetworkType][]*infrav1.NetworkDeviceSpec, error) {

	// Determine zone
	if ctx.VSphereCluster == nil {
		ctx.Logger.V(4).Info("cluster infrastructure missing")
		return nil, fmt.Errorf("cluster infrastructure missing for machine %q in namespace %q", ctx.VSphereMachine.Name, ctx.VSphereMachine.Namespace)
	}

	isManagementZone := ctx.VSphereCluster.Spec.CloudProviderConfiguration.Labels.Zone == ManagementZoneName

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
