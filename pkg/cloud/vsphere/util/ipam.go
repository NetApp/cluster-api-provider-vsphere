package util

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

func GetNetworkType(machine infrav1.VSphereMachine, managementZone bool, networkName string) (ipam.NetworkType, error) {
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

func GetIPAMAgent(logger logr.Logger, c client.Client) (ipam.Agent, error) {

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
