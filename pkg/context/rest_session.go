package context

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"

	apiv1 "k8s.io/api/core/v1"
	"sigs.k8s.io/cluster-api-provider-vsphere/api/v1alpha2"
	"sigs.k8s.io/cluster-api-provider-vsphere/pkg/constants"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NetApp
var restSessionCache = map[string]RestSession{}
var restSessionMU sync.Mutex

// NetApp
type RestSession struct {
	*rest.Client
}

// NetApp
func getOrCreateCachedRESTSession(ctx *MachineContext) (*RestSession, error) {
	restSessionMU.Lock()
	defer restSessionMU.Unlock()

	server := ctx.VSphereCluster.Spec.Server
	datacenter := ctx.VSphereMachine.Spec.Datacenter
	sessionKey := server + ctx.Username + datacenter

	if session, ok := restSessionCache[sessionKey]; ok {
		if ok := session.IsActive(); ok {
			ctx.Logger.V(4).Info("using cached vSphere REST client session", "server", server, "user", ctx.Username)
			return &session, nil
		}
	}

	soapURL, err := soap.ParseURL(server)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing vSphere URL %q", server)
	}
	if soapURL == nil {
		return nil, errors.Errorf("error parsing vSphere URL %q", server)
	}

	soapClient := soap.NewClient(soapURL, true)
	vimClient, err := vim25.NewClient(ctx, soapClient)
	if err != nil {
		return nil, errors.Wrapf(err, "error setting up new vSphere SOAP client")
	}

	ctx.Logger.V(2).Info("creating new vSphere REST client session", "server", server, "user", ctx.Username)
	restClient := rest.NewClient(vimClient)
	if err := restClient.Login(ctx, url.UserPassword(ctx.Username, ctx.Password)); err != nil {
		return nil, errors.Wrapf(err, "error logging in with REST client for user %q", ctx.Username)
	}

	session := RestSession{Client: restClient}

	session.UserAgent = v1alpha2.GroupVersion.String()

	// Cache the session.
	restSessionCache[sessionKey] = session
	ctx.Logger.V(2).Info("cached vSphere REST client session", "server", server, "user", ctx.Username)

	return &session, nil
}

// NetApp
func (s *RestSession) IsActive() bool {

	// NOTE: Rest client does not expose an IsActive check out of the box. Rolling our own rudimentary one.

	tm := tags.NewManager(s.Client)

	_, err := tm.GetTags(context.TODO())
	if err != nil {
		return false
	}

	return true
}

// NetApp
func GetVSphereCredentials(logger logr.Logger, c client.Client, cluster *clusterv1.Cluster) (string, string, error) {

	const credentialSecretNameAnnotationKey = "cluster-api-vsphere-credentials-secret-name"
	secretName, ok := cluster.Annotations[credentialSecretNameAnnotationKey]
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
