package utils

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vapi/tags"
	"github.com/vmware/govmomi/vim25/types"
	"k8s.io/klog"
)

// NetApp
const (
	categoryName               = "NKS"
	clusterInfoTagNameTemplate = "nks.workspaceid.%s.clusterid.%s.clustername.%s"
	serviceClusterTagName      = "nks.service.cluster"
)

// NetApp
func TagWithClusterInfo(ctx context.Context, tm *tags.Manager, moref types.ManagedObjectReference, workspaceID string, clusterID string, clusterName string) error {

	tagName := fmt.Sprintf(clusterInfoTagNameTemplate, workspaceID, clusterID, clusterName)

	tag, err := getOrCreateNKSTag(ctx, tm, tagName)
	if err != nil {
		return err
	}

	err = tm.AttachTag(ctx, tag.ID, moref)
	if err != nil {
		return errors.Wrapf(err, "could not attach tag %s to object", tag.Name)
	}

	return nil
}

// NetApp
func TagAsServiceCluster(ctx context.Context, tm *tags.Manager, moref types.ManagedObjectReference) error {

	tag, err := getOrCreateNKSTag(ctx, tm, serviceClusterTagName)
	if err != nil {
		return err
	}

	err = tm.AttachTag(ctx, tag.ID, moref)
	if err != nil {
		return errors.Wrapf(err, "could not attach tag %s to object", tag.Name)
	}

	return nil
}

// NetApp
func getOrCreateNKSTag(ctx context.Context, tm *tags.Manager, tagName string) (*tags.Tag, error) {

	tag, err := tm.GetTag(ctx, tagName)
	if err == nil && tag != nil {
		return tag, nil
	}

	nksCategory, err := getOrCreateNKSTagCategory(ctx, tm)
	if err != nil {
		return nil, errors.Wrap(err, "could not get NKS tag category")
	}

	newTag := &tags.Tag{
		Name:        tagName,
		Description: "NKS tag",
		CategoryID:  nksCategory.ID,
	}

	klog.V(4).Infof("creating vSphere tag %s", newTag.Name)
	_, err = tm.CreateTag(ctx, newTag)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create tag %s", newTag)
	}

	tag, err = tm.GetTag(ctx, tagName)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get tag with name %s", tagName)
	}

	return tag, nil
}

// NetApp
func getOrCreateNKSTagCategory(ctx context.Context, tm *tags.Manager) (*tags.Category, error) {

	category, err := tm.GetCategory(ctx, categoryName)
	if err == nil && category != nil {
		return category, nil
	}

	newCategory := &tags.Category{
		Name:        categoryName,
		Description: "NKS tag category",
		Cardinality: "MULTIPLE",
		AssociableTypes: []string{
			"Folder",
			"VirtualMachine",
		},
	}

	klog.V(4).Infof("creating vSphere tag category %s", newCategory.Name)
	_, err = tm.CreateCategory(ctx, newCategory)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create tag category %s", newCategory)
	}

	category, err = tm.GetCategory(ctx, categoryName)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get tag category with name %s", categoryName)
	}

	return category, nil
}
