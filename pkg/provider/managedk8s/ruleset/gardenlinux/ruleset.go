// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenlinux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/gardener/gardener/pkg/utils/retry"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/imagevector"
	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/kubernetes/pod"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	gardenlinuxpod "github.com/gardener/diki/pkg/provider/managedk8s/ruleset/gardenlinux/pod"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	"github.com/gardener/diki/pkg/shared/images"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

const (
	// RulesetID is a constant containing the id of the Gardenlinux Ruleset.
	RulesetID = "gardenlinux"
	// RulesetName is a constant containing the user-friendly name of the Gardenlinux ruleset.
	RulesetName = "Gardenlinux Testing Framework"
)

var (
	_ ruleset.Ruleset = &Ruleset{}
	// SupportedVersions is a list of available versions for the Gardenlinux Ruleset.
	// Versions are sorted from newest to oldest.
	// TODO(georgibaltiev): introduce support for actual gardenlinux versions and remove dummy values
	SupportedVersions = []string{"v0.1.0"}
)

// Ruleset implements the Gardenlinux Testing Framework ruleset.
type Ruleset struct {
	version           string
	Config            *rest.Config
	Client            client.Client
	ClusterPodContext pod.SimplePodContext
	args              Args
	instanceID        string
	logger            *slog.Logger
}

// Args are Ruleset specific arguments.
type Args struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		instanceID: uuid.New().String(),
	}

	for _, o := range options {
		o(r)
	}

	if r.logger == nil {
		r.logger = slog.Default().With("ruleset", r.ID(), "version", r.Version())
	}

	c, err := client.New(r.Config, client.Options{})
	if err != nil {
		return nil, err
	}
	r.Client = c

	podContext, err := gardenlinuxpod.NewPodContext(r.Client, r.Config, nil)
	if err != nil {
		return nil, err
	}
	r.ClusterPodContext = *podContext

	return r, nil
}

// ID returns the id of the Ruleset.
func (r *Ruleset) ID() string {
	return RulesetID
}

// Name returns the name of the Ruleset.
func (r *Ruleset) Name() string {
	return RulesetName
}

// Version returns the version of the Ruleset.
func (r *Ruleset) Version() string {
	return r.version
}

// FromGenericConfig creates a Ruleset from a RulesetConfig
func FromGenericConfig(rulesetConfig config.RulesetConfig, managedConfig *rest.Config, fldPath *field.Path) (*Ruleset, error) {
	if errs := ValidateRulesetConfig(rulesetConfig, fldPath); len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	rulesetArgsByte, err := json.Marshal(rulesetConfig.Args)
	if err != nil {
		return nil, err
	}

	var rulesetArgs Args
	if err := json.Unmarshal(rulesetArgsByte, &rulesetArgs); err != nil {
		return nil, err
	}

	ruleset, err := New(
		WithVersion(rulesetConfig.Version),
		WithConfig(managedConfig),
		WithArgs(rulesetArgs),
	)
	if err != nil {
		return nil, err
	}
	return ruleset, nil
}

// ValidateRulesetConfig validates a [config.RulesetConfig].
func ValidateRulesetConfig(rulesetConfig config.RulesetConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if !slices.Contains(SupportedVersions, rulesetConfig.Version) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("version"), rulesetConfig.Version, SupportedVersions))
	}

	rulesetArgsByte, err := json.Marshal(rulesetConfig.Args)
	if err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), rulesetConfig.Args, err.Error()))
	}

	var rulesetArgs Args
	if err := json.Unmarshal(rulesetArgsByte, &rulesetArgs); err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), rulesetConfig.Args, err.Error()))
	}

	allErrs = append(allErrs, disaoption.ValidateLabelNames(rulesetArgs.NodeGroupByLabels, fldPath.Child("args", "nodeGroupByLabels"))...)

	if len(rulesetConfig.RuleOptions) > 0 {
		allErrs = append(allErrs, field.Forbidden(fldPath.Child("ruleOptions"), "the gardenlinux ruleset does not accept per-rule options"))
	}

	return allErrs
}

// RunRule executes specific Rule of a known Ruleset.
// The function is not supported for this ruleset, since the implementation of the framework is external.
func (r *Ruleset) RunRule(_ context.Context, _ string) (rule.RuleResult, error) {
	return rule.RuleResult{}, fmt.Errorf("the gardenlinux ruleset does not support running rules individually")
}

// Run deploys the gardenlinux test Pod on every selected Node in parallel and merges the collected test results into a single RulesetResult.
func (r *Ruleset) Run(ctx context.Context) (ruleset.RulesetResult, error) {
	testImage, err := imagevector.ImageVector().FindImage(images.GardenlinuxTestImageName)
	if err != nil {
		return ruleset.RulesetResult{}, fmt.Errorf("failed to find image version for %s: %w", images.GardenlinuxTestImageName, err)
	}
	testImage.WithOptionalTag(r.version)

	sidecarImage, err := imagevector.ImageVector().FindImage(images.DikiOpsImageName)
	if err != nil {
		return ruleset.RulesetResult{}, fmt.Errorf("failed to find image version for %s: %w", images.DikiOpsImageName, err)
	}

	nodes, err := kubeutils.GetNodes(ctx, r.Client, 300)
	if err != nil {
		return ruleset.RulesetResult{}, err
	}

	allClusterPods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return ruleset.RulesetResult{}, err
	}

	nodesAllocatablePods := kubeutils.GetNodesAllocatablePodsNum(allClusterPods, nodes)
	selectedNodes, _ := kubeutils.SelectNodes(nodes, nodesAllocatablePods, r.args.NodeGroupByLabels)

	type rulesetRun struct {
		result   ruleset.RulesetResult
		err      error
		nodeName string
	}

	var (
		rulesetResults []ruleset.RulesetResult
		wg             sync.WaitGroup
		resultCh       = make(chan rulesetRun)
	)

	for _, node := range selectedNodes {
		wg.Go(func() {
			result, err := r.runOnNode(ctx, node.Name, testImage.String(), sidecarImage.String())
			resultCh <- rulesetRun{result: result, err: err, nodeName: node.Name}
		})
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	finishMsg := "finished ruleset run"
	resultCount := 0
	for rulesetRun := range resultCh {
		resultCount++
		remaining := len(selectedNodes) - resultCount
		if rulesetRun.err != nil {
			r.Logger().Error(finishMsg, "ruleset_id", RulesetID, "node_name", rulesetRun.nodeName, "remaining_nodes", remaining, "error", rulesetRun.err)
			err = errors.Join(err, fmt.Errorf("ruleset %s on node %s errored: %w", RulesetID, rulesetRun.nodeName, rulesetRun.err))
		} else {
			r.Logger().Info(finishMsg, "ruleset_id", RulesetID, "node_name", rulesetRun.nodeName, "remaining_nodes", remaining)
			rulesetResults = append(rulesetResults, rulesetRun.result)
		}
	}

	if err := ctx.Err(); err != nil {
		return ruleset.RulesetResult{}, err
	}

	// TODO: maybe return both result and err
	if err != nil {
		return ruleset.RulesetResult{}, err
	}

	// TODO (georgibaltiev): return a merged RulesetResult, based on the gathered results from the slices
	if len(rulesetResults) == 0 {
		return ruleset.RulesetResult{}, nil
	}
	return rulesetResults[0], nil
}

func (r *Ruleset) runOnNode(ctx context.Context, nodeName, testImage, sidecarImage string) (ruleset.RulesetResult, error) {
	podName := fmt.Sprintf("test-%s-%s", r.ID(), sharedrules.Generator.Generate(10))

	defer func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), r.ClusterPodContext.WaitTimeout)
		defer cancel()

		if err := r.ClusterPodContext.Delete(timeoutCtx, podName, gardenlinuxpod.SystemNamespace); err != nil {
			r.Logger().Error(err.Error())
		}
	}()

	additionalLabels := map[string]string{pod.LabelInstanceID: r.instanceID}

	podExecutor, err := r.ClusterPodContext.Create(ctx, gardenlinuxpod.NewTestPod(podName, testImage, sidecarImage, nodeName, additionalLabels))
	if err != nil {
		return ruleset.RulesetResult{}, fmt.Errorf("failed to create test pod on node %s: %w", nodeName, err)
	}

	// TODO (georgibaltiev): Add parsing logic for the report result. Remove the currently defaulted empty RuleResult
	if _, err = r.readReport(ctx, podExecutor, podName); err != nil {
		return ruleset.RulesetResult{}, fmt.Errorf("failed to read test report on node %s: %w", nodeName, err)
	}

	return ruleset.RulesetResult{}, nil
}

func (r *Ruleset) readReport(ctx context.Context, podExecutor pod.PodExecutor, podName string) (string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, r.ClusterPodContext.WaitTimeout)
	defer cancel()

	var report string
	if err := retry.Until(timeoutCtx, r.ClusterPodContext.WaitInterval, func(ctx context.Context) (bool, error) {
		terminated, err := r.testContainerTerminated(ctx, podName)
		if err != nil {
			return retry.MinorError(err)
		}
		if !terminated {
			return retry.MinorError(fmt.Errorf("gardenlinux test container %q has not terminated yet", gardenlinuxpod.TestContainerName))
		}

		report, err = podExecutor.Execute(ctx, "/bin/busybox cat /tests/tests/output/test.xml", "")
		if err != nil {
			return retry.MinorError(err)
		}
		return retry.Ok()
	}); err != nil {
		return "", fmt.Errorf("failed to read gardenlinux test report %s: %w", gardenlinuxpod.ReportFilename, err)
	}

	return report, nil
}

func (r *Ruleset) testContainerTerminated(ctx context.Context, podName string) (bool, error) {
	testPod := &corev1.Pod{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: gardenlinuxpod.SystemNamespace, Name: podName}, testPod); err != nil {
		return false, err
	}

	for _, status := range testPod.Status.ContainerStatuses {
		if status.Name == gardenlinuxpod.TestContainerName {
			return status.State.Terminated != nil, nil
		}
	}

	return false, nil
}

// Logger returns the Ruleset's logger.
func (r *Ruleset) Logger() *slog.Logger {
	return r.logger
}
