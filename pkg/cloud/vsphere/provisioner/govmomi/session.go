package govmomi

import (
	"context"
	"fmt"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"
	"k8s.io/klog"
	"net/url"
	vsphereutils "sigs.k8s.io/cluster-api-provider-vsphere/pkg/cloud/vsphere/utils"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
)

type SessionContext struct {
	session *govmomi.Client
	context *context.Context
	finder  *find.Finder
}

// NetApp
type RestSessionContext struct {
	restClient *rest.Client
}

func (pv *Provisioner) sessionFromProviderConfig(cluster *clusterv1.Cluster, machine *clusterv1.Machine) (*SessionContext, error) {
	var sc SessionContext
	vsphereConfig, err := vsphereutils.GetClusterProviderSpec(cluster.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}
	username, password, err := pv.GetVsphereCredentials(cluster)
	if err != nil {
		return nil, err
	}
	if ses, ok := pv.sessioncache[vsphereConfig.VsphereServer+username]; ok {
		s, ok := ses.(SessionContext)
		if ok {
			// Test if the session is valid and return
			if ok, _ := s.session.SessionManager.SessionIsActive(*s.context); ok {
				return &s, nil
			}
		}
	}
	ctx := context.Background()

	soapURL, err := soap.ParseURL(vsphereConfig.VsphereServer)
	if soapURL == nil || err != nil {
		return nil, fmt.Errorf("error parsing vSphere URL %s : [%s]", soapURL, err)
	}
	// Set the credentials
	soapURL.User = url.UserPassword(username, password)
	// Temporarily setting the insecure flag True
	// TODO(ssurana): handle the certs better
	sc.session, err = govmomi.NewClient(ctx, soapURL, true)
	if err != nil {
		return nil, fmt.Errorf("error setting up new vSphere SOAP client: %s", err)
	}
	sc.context = &ctx
	finder := find.NewFinder(sc.session.Client, false)
	sc.finder = finder
	pv.sessioncache[vsphereConfig.VsphereServer+username] = sc
	return &sc, nil
}

// NetApp
func (pv *Provisioner) restClientFromProviderConfig(cluster *clusterv1.Cluster) (*rest.Client, error) {

	var rsc RestSessionContext
	ctx := context.Background()

	vsphereConfig, err := vsphereutils.GetClusterProviderSpec(cluster.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}

	username, password, err := pv.GetVsphereCredentials(cluster)
	if err != nil {
		return nil, err
	}

	if cachedClientContext, ok := pv.restsessioncache[vsphereConfig.VsphereServer+username]; ok {
		cachedClientContext, ok := cachedClientContext.(RestSessionContext)
		if ok {
			if ok := restClientActive(cachedClientContext.restClient); ok {
				klog.V(4).Infof("using cached rest client for server %s and user %s", vsphereConfig.VsphereServer, username)
				return cachedClientContext.restClient, nil
			}
		}
	}

	soapURL, err := soap.ParseURL(vsphereConfig.VsphereServer)
	if soapURL == nil || err != nil {
		return nil, fmt.Errorf("error parsing vSphere URL %s : [%s]", soapURL, err)
	}

	soapClient := soap.NewClient(soapURL, true)
	vimClient, err := vim25.NewClient(ctx, soapClient)
	if err != nil {
		return nil, err
	}

	klog.V(4).Infof("creating new rest client for server %s and user %s", vsphereConfig.VsphereServer, username)
	restClient := rest.NewClient(vimClient)
	if err := restClient.Login(ctx, url.UserPassword(username, password)); err != nil {
		return nil, err
	}

	rsc.restClient = restClient

	pv.restsessioncache[vsphereConfig.VsphereServer+username] = rsc

	return restClient, nil
}

// NetApp
func restClientActive(client *rest.Client) bool {

	// NOTE: Rest client does not expose an IsActive check out of the box. Rolling our own rudimentary one.

	tm := tags.NewManager(client)

	_, err := tm.GetTags(context.TODO())
	if err != nil {
		return false
	}

	return true
}
