// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	stringgen "github.com/gardener/diki/pkg/internal/stringgen"
	"github.com/gardener/diki/pkg/rule"
)

var _ PodContext = &PodWorkerPool{}

// SelectNodesFn matches the signature of kubeutils.SelectNodes.
type SelectNodesFn func(
	nodes []corev1.Node,
	nodesAllocatablePods map[string]int,
	labels []string,
) ([]corev1.Node, []rule.CheckResult)

// SelectPodOfReferenceGroupFn matches the signature of kubeutils.SelectPodOfReferenceGroup.
type SelectPodOfReferenceGroupFn func(
	pods []corev1.Pod,
	replicaSets []appsv1.ReplicaSet,
	nodesAllocatablePods map[string]int,
	target rule.Target,
) (map[string][]corev1.Pod, []rule.CheckResult)

// NodeConstructorFn builds a pod-constructor closure for the given node.
type NodeConstructorFn func(nodeName string) func() *corev1.Pod

// NamedPodExecutor wraps a PodExecutor and carries the actual pod name and namespace.
// Rules that need to look up the exec pod by name after creation can type-assert the
// PodExecutor returned by PodWorkerPool.Create to *NamedPodExecutor to get the real name.
type NamedPodExecutor struct {
	PodExecutor
	PodName      string
	PodNamespace string
}

type podRecord struct {
	name      string
	namespace string
}

// PodWorkerPool is a PodContext implementation that creates pods lazily —
// at most one pod per node — and reuses the running pod across multiple rules.
// Delete is a no-op, all cleanup is done via CleanupAll after all rules finish.
type PodWorkerPool struct {
	podContext                  PodContext
	selectNodesFn               SelectNodesFn
	selectPodOfReferenceGroupFn SelectPodOfReferenceGroupFn
	nodeConstructorFn           NodeConstructorFn
	Generator                   stringgen.StringGenerator
	mu                          sync.Mutex // protects executors, podNames
	executors                   map[string]PodExecutor
	podNames                    map[string]podRecord
}

// NewPodWorkerPool creates a new PodWorkerPool backed by the given PodContext.
func NewPodWorkerPool(
	podContext PodContext,
	selectNodesFn SelectNodesFn,
	selectPodOfReferenceGroupFn SelectPodOfReferenceGroupFn,
	nodeConstructorFn NodeConstructorFn,
) *PodWorkerPool {
	return &PodWorkerPool{
		podContext:                  podContext,
		selectNodesFn:               selectNodesFn,
		selectPodOfReferenceGroupFn: selectPodOfReferenceGroupFn,
		nodeConstructorFn:           nodeConstructorFn,
		Generator:                   stringgen.Default(),
		executors:                   map[string]PodExecutor{},
		podNames:                    map[string]podRecord{},
	}
}

// SelectNodes adjusts allocatable pod counts to prefer nodes that already have a
// pooled executor, delegates to the injected SelectNodesFn, and eagerly creates
// pods on the selected nodes so that subsequent rules see the same pool state.
func (p *PodWorkerPool) SelectNodes(
	ctx context.Context,
	nodes []corev1.Node,
	nodesAllocatablePods map[string]int,
	labels []string,
) ([]corev1.Node, []rule.CheckResult) {
	defer p.mu.Unlock()
	p.mu.Lock()

	adjusted := p.adjustAllocatablePods(nodesAllocatablePods)
	selectedNodes, checks := p.selectNodesFn(nodes, adjusted, labels)

	for _, node := range selectedNodes {
		_, err := p.create(ctx, p.nodeConstructorFn(node.Name))
		if err != nil {
			checks = append(checks, rule.ErroredCheckResult(err.Error(), rule.NewTarget()))
		}
	}

	return selectedNodes, checks
}

// SelectPodOfReferenceGroup adjusts allocatable pod counts to prefer nodes that
// already have a pooled executor, delegates to the injected SelectPodOfReferenceGroupFn,
// and eagerly creates pods on the selected nodes.
func (p *PodWorkerPool) SelectPodOfReferenceGroup(
	ctx context.Context,
	pods []corev1.Pod,
	replicaSets []appsv1.ReplicaSet,
	nodesAllocatablePods map[string]int,
	target rule.Target,
) (map[string][]corev1.Pod, []rule.CheckResult) {
	defer p.mu.Unlock()
	p.mu.Lock()

	adjusted := p.adjustAllocatablePods(nodesAllocatablePods)
	groupedPods, checks := p.selectPodOfReferenceGroupFn(pods, replicaSets, adjusted, target)

	for nodeName := range groupedPods {
		_, err := p.create(ctx, p.nodeConstructorFn(nodeName))
		if err != nil {
			checks = append(checks, rule.ErroredCheckResult(err.Error(), target))
		}
	}

	return groupedPods, checks
}

// Create returns a PodExecutor for the node targeted by constructorFn.
// If a pod has already been created for that node it is reused; otherwise a new pod
// is created via the underlying PodContext.
// The returned PodExecutor is always a *NamedPodExecutor so callers can retrieve the
// actual pod name via a type assertion.
func (p *PodWorkerPool) Create(ctx context.Context, constructorFn func() *corev1.Pod) (PodExecutor, error) {
	defer p.mu.Unlock()
	p.mu.Lock()

	return p.create(ctx, constructorFn)
}

func (p *PodWorkerPool) create(ctx context.Context, constructorFn func() *corev1.Pod) (PodExecutor, error) {
	podSpec := constructorFn()
	nodeName := podSpec.Spec.NodeSelector["kubernetes.io/hostname"]

	if executor, exists := p.executors[nodeName]; exists {
		rec := p.podNames[nodeName]
		return &NamedPodExecutor{
			PodExecutor:  executor,
			PodName:      rec.name,
			PodNamespace: rec.namespace,
		}, nil
	}

	h := fnv.New32a()
	if _, err := h.Write([]byte(nodeName)); err != nil {
		return nil, err
	}
	podSpec.Name = fmt.Sprintf("diki-pool-%08x-%s", h.Sum32(), p.Generator.Generate(10))

	modifiedConstructor := func() *corev1.Pod {
		return podSpec
	}

	executor, err := p.podContext.Create(ctx, modifiedConstructor)
	if err != nil {
		return nil, err
	}

	p.executors[nodeName] = executor
	p.podNames[nodeName] = podRecord{name: podSpec.Name, namespace: podSpec.Namespace}

	return &NamedPodExecutor{
		PodExecutor:  executor,
		PodName:      podSpec.Name,
		PodNamespace: podSpec.Namespace,
	}, nil
}

// Delete is a no-op. Pod lifecycle is managed by the pool.
func (p *PodWorkerPool) Delete(_ context.Context, _, _ string) error {
	return nil
}

// CleanupAll deletes all pods that were created by this pool.
func (p *PodWorkerPool) CleanupAll(ctx context.Context) error {
	p.mu.Lock()
	records := make([]podRecord, 0, len(p.podNames))
	for _, rec := range p.podNames {
		records = append(records, rec)
	}
	p.mu.Unlock()

	var (
		errCh = make(chan error, len(records))
		wg    sync.WaitGroup
	)

	for _, rec := range records {
		wg.Add(1)
		go func(rec podRecord) {
			defer wg.Done()
			if err := p.podContext.Delete(ctx, rec.name, rec.namespace); err != nil {
				errCh <- err
			}
		}(rec)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// adjustAllocatablePods returns a copy of nodesAllocatablePods where nodes that already
// have a pooled executor are given a high allocatable count.
// Caller must hold p.mu.
func (p *PodWorkerPool) adjustAllocatablePods(nodesAllocatablePods map[string]int) map[string]int {
	adjusted := maps.Clone(nodesAllocatablePods)
	for nodeName := range p.executors {
		if _, exists := adjusted[nodeName]; exists {
			adjusted[nodeName] = 1 << 20 // large enough to always win the selection
		}
	}
	return adjusted
}
