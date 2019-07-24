package tags

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

// TODO Use logger from machinecontext

// NetApp
// TODO Take in machinecontext here instead?
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
// DeleteClusterInfoTagAndCategoryIfNoSubjects deletes the cluster info tag if there are no subjects tied to the tag, i.e. no objects are tagged with that tag
// It also deletes the tag category if there are no tags left in the category
func DeleteClusterInfoTagAndCategoryIfNoSubjects(ctx context.Context, tm *tags.Manager, workspaceID string, clusterID string, clusterName string) error {

	tagName := fmt.Sprintf(clusterInfoTagNameTemplate, workspaceID, clusterID, clusterName)

	tag, err := tm.GetTag(ctx, tagName)
	if err != nil {
		return errors.Wrapf(err, "could not get tag with name %s", tagName)
	}

	return deleteNKSTagIfNoSubjects(ctx, tm, tag)
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
// DeleteServiceClusterTagAndCategoryIfNoSubjects deletes the service cluster tag if there are no subjects tied to the tag, i.e. no objects are tagged with that tag
// It also deletes the tag category if there are no tags left in the category
func DeleteServiceClusterTagAndCategoryIfNoSubjects(ctx context.Context, tm *tags.Manager) error {

	tag, err := tm.GetTag(ctx, serviceClusterTagName)
	if err != nil {
		return errors.Wrapf(err, "could not get tag with name %s", serviceClusterTagName)
	}

	return deleteNKSTagIfNoSubjects(ctx, tm, tag)
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

// NetApp
func deleteNKSTagIfNoSubjects(ctx context.Context, tm *tags.Manager, tag *tags.Tag) error {

	attachedObjects, err := tm.ListAttachedObjects(ctx, tag.ID)
	if err != nil {
		return errors.Wrapf(err, "could not list attached objects for tag with name %s", tag.Name)
	}

	if len(attachedObjects) == 0 {

		klog.V(4).Infof("deleting tag %s", tag.Name)
		err := tm.DeleteTag(ctx, tag)
		if err != nil {
			return errors.Wrapf(err, "could not delete tag with name %s")
		}

		category, err := tm.GetCategory(ctx, tag.CategoryID)
		if err != nil {
			return errors.Wrapf(err, "could not get category with ID %s", tag.CategoryID)
		}

		err = deleteNKSTagCategoryIfNoSubjects(ctx, tm, category)
		if err != nil {
			return errors.Wrapf(err, "could not delete category for tag %s with name %s", tag.Name, category.Name)
		}

		return nil
	}

	klog.V(4).Infof("will not delete tag with name %s - still used by %d objects", tag.Name, len(attachedObjects))
	return nil
}

// NetApp
func deleteNKSTagCategoryIfNoSubjects(ctx context.Context, tm *tags.Manager, category *tags.Category) error {

	tagsInCategory, err := tm.GetTagsForCategory(ctx, category.Name)
	if err != nil {
		return errors.Wrapf(err, "could not get tags for category with name %s", category.Name)
	}

	if len(tagsInCategory) == 0 {
		klog.V(4).Infof("deleting category %s", category.Name)
		err := tm.DeleteCategory(ctx, category)
		if err != nil {
			return errors.Wrapf(err, "could not delete category with name %s", category.Name)
		}
		return nil
	}

	klog.V(4).Infof("will not delete tag category with name %s - still used by %d tags", category.Name, len(tagsInCategory))
	return nil
}
