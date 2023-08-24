// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/diki/pkg/kubernetes/pod"
)

// FakeSimplePodContext is used to fake the work of SimplePodContext.
type FakeSimplePodContext struct {
	executeReturnString [][]string
	executeReturnError  [][]error
	createCount         int
}

// NewFakeSimplePodContext creates a new FakeSimplePodContext.
func NewFakeSimplePodContext(executeReturnString [][]string, executeReturnError [][]error) *FakeSimplePodContext {
	return &FakeSimplePodContext{
		executeReturnString: executeReturnString,
		executeReturnError:  executeReturnError,
	}
}

// Create returns the preset values.
func (mspc *FakeSimplePodContext) Create(_ context.Context, _ func() *corev1.Pod) (pod.PodExecutor, error) {
	if mspc.createCount >= len(mspc.executeReturnString) {
		return nil, errors.New("not enough return strings have been faked")
	}
	if mspc.createCount >= len(mspc.executeReturnError) {
		return nil, errors.New("not enough return errors have been faked")
	}
	mspc.createCount++
	return NewFakePodExecutor(mspc.executeReturnString[mspc.createCount-1], mspc.executeReturnError[mspc.createCount-1]), nil
}

// Delete always returns nil.
func (mspc *FakeSimplePodContext) Delete(_ context.Context, _, _ string) error {
	return nil
}

// FakePodExecutor is used to fake the work of PodExecutor.
type FakePodExecutor struct {
	executeReturnString []string
	executeReturnError  []error
	executeCount        int
}

// NewFakePodExecutor creates a new FakePodExecutor.
func NewFakePodExecutor(executeReturnString []string, executeReturnError []error) *FakePodExecutor {
	return &FakePodExecutor{
		executeReturnString: executeReturnString,
		executeReturnError:  executeReturnError,
		executeCount:        0,
	}
}

// Execute returns the preset values.
func (mpe *FakePodExecutor) Execute(_ context.Context, _ string, _ string) (string, error) {
	if mpe.executeCount >= len(mpe.executeReturnString) {
		return "", errors.New("not enough return strings have been faked")
	}
	if mpe.executeCount >= len(mpe.executeReturnError) {
		return "", errors.New("not enough return errors have been faked")
	}
	mpe.executeCount++
	return mpe.executeReturnString[mpe.executeCount-1], mpe.executeReturnError[mpe.executeCount-1]
}
