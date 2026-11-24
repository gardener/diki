// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

var (
	_ rule.Rule              = &RulePSSB007{}
	_ rule.Severity          = &RulePSSB007{}
	_ option.Option          = &OptionsPSSB007{}
	_ option.MergeableOption = &OptionsPSSB007{}
)

type RulePSSB007 struct {
	Client  client.Client
	Options *OptionsPSSB007
}

type OptionsPSSB007 struct {
	AcceptedPods []option.AcceptedNamespacedObject `json:"acceptedPods" yaml:"acceptedPods"`
}

// Validate validates that option configurations are correctly defined.
func (o OptionsPSSB007) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedPodsPath := fldPath.Child("acceptedPods")

	for pIdx, p := range o.AcceptedPods {
		allErrs = append(allErrs, p.Validate(acceptedPodsPath.Index(pIdx))...)
	}

	return allErrs
}

// Merge returns a new OptionsPSSB007 that is the result of merging other into the receiver.
// AcceptedPods slices are concatenated. If other is not *OptionsPSSB007, an error is returned.
func (o *OptionsPSSB007) Merge(other option.MergeableOption) (option.MergeableOption, error) {
	if option.IsNilValue(other) {
		return o, nil
	}

	otherOpts, err := option.AssertSameType[*OptionsPSSB007](other)
	if err != nil {
		return nil, err
	}

	merged := &OptionsPSSB007{
		AcceptedPods: make([]option.AcceptedNamespacedObject, 0, len(o.AcceptedPods)+len(otherOpts.AcceptedPods)),
	}
	merged.AcceptedPods = append(merged.AcceptedPods, o.AcceptedPods...)
	merged.AcceptedPods = append(merged.AcceptedPods, otherOpts.AcceptedPods...)

	return merged, nil
}

func (r *RulePSSB007) ID() string {
	return "PSS-B007"
}

func (r *RulePSSB007) Name() string {
	return "Host Probes / Lifecycle Hooks"
}

func (r *RulePSSB007) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

// Run implements [rule.Rule].
func (r *RulePSSB007) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	pods, err := kubeutils.GetPods(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "PodList"))), nil
	}

	if len(pods) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Pods.", rule.NewTarget())), nil
	}

	filteredPods := kubeutils.FilterPodsByOwnerRef(pods)

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	replicaSets, err := kubeutils.GetReplicaSets(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ReplicaSetList"))), nil
	}

	for _, pod := range filteredPods {
		var (
			podCheckResults []rule.CheckResult
			podTarget       = kubeutils.TargetWithPod(rule.NewTarget(), pod, replicaSets)
		)

		reportHost := func(containerName, handler, probeType, host string) error {
			target := podTarget.With("container", containerName, "details", fmt.Sprintf("%s.%s.host: %s", handler, probeType, host))
			if accepted, justification, err := r.accepted(pod.Labels, namespaces[pod.Namespace].Labels); err != nil {
				return err
			} else if accepted {
				msg := cmp.Or(justification, "Pod accepted to set a host in probes or lifecycle hooks.")
				podCheckResults = append(podCheckResults, rule.AcceptedCheckResult(msg, target))
			} else {
				podCheckResults = append(podCheckResults, rule.FailedCheckResult("Pod must not set a host in probes or lifecycle hooks.", target))
			}
			return nil
		}

		checkHandler := func(containerName, handler string, httpGet *corev1.HTTPGetAction, tcpSocket *corev1.TCPSocketAction) error {
			if httpGet != nil && httpGet.Host != "" {
				if err := reportHost(containerName, handler, "httpGet", httpGet.Host); err != nil {
					return err
				}
			}
			if tcpSocket != nil && tcpSocket.Host != "" {
				if err := reportHost(containerName, handler, "tcpSocket", tcpSocket.Host); err != nil {
					return err
				}
			}
			return nil
		}

		checkContainer := func(containerName string, livenessProbe, readinessProbe, startupProbe *corev1.Probe, lifecycle *corev1.Lifecycle) error {
			for _, p := range []struct {
				name  string
				probe *corev1.Probe
			}{
				{"livenessProbe", livenessProbe},
				{"readinessProbe", readinessProbe},
				{"startupProbe", startupProbe},
			} {
				if p.probe == nil {
					continue
				}
				if err := checkHandler(containerName, p.name, p.probe.HTTPGet, p.probe.TCPSocket); err != nil {
					return err
				}
			}

			if lifecycle != nil {
				if lifecycle.PostStart != nil {
					if err := checkHandler(containerName, "lifecycle.postStart", lifecycle.PostStart.HTTPGet, lifecycle.PostStart.TCPSocket); err != nil {
						return err
					}
				}
				if lifecycle.PreStop != nil {
					if err := checkHandler(containerName, "lifecycle.preStop", lifecycle.PreStop.HTTPGet, lifecycle.PreStop.TCPSocket); err != nil {
						return err
					}
				}
			}
			return nil
		}

		for _, container := range slices.Concat(pod.Spec.Containers, pod.Spec.InitContainers) {
			if err := checkContainer(container.Name, container.LivenessProbe, container.ReadinessProbe, container.StartupProbe, container.Lifecycle); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}
		for _, ephemeralContainer := range pod.Spec.EphemeralContainers {
			if err := checkContainer(ephemeralContainer.Name, ephemeralContainer.LivenessProbe, ephemeralContainer.ReadinessProbe, ephemeralContainer.StartupProbe, ephemeralContainer.Lifecycle); err != nil {
				return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), nil
			}
		}

		if len(podCheckResults) == 0 {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod does not set a host in probes or lifecycle hooks.", podTarget))
		}
		checkResults = append(checkResults, podCheckResults...)
	}

	return rule.Result(r, checkResults...), nil
}

func (r *RulePSSB007) accepted(podLabels, namespaceLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedPod := range r.Options.AcceptedPods {
		if matches, err := acceptedPod.Matches(podLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches {
			return true, acceptedPod.Justification, nil
		}
	}

	return false, "", nil
}
