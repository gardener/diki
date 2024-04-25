// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gardener/gardener/pkg/utils/retry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PodExecutor executes commands inside a pod.
type PodExecutor interface {
	Execute(ctx context.Context, command string, commandArg string) (string, error)
}

// PodContext creates and deletes Pods.
type PodContext interface {
	Create(ctx context.Context, podConstructorFn func() *corev1.Pod) (PodExecutor, error)
	Delete(ctx context.Context, name, namespace string) error
}

// SimplePodExecutor can execute commands in a pod.
type SimplePodExecutor struct {
	name      string
	namespace string
	client    client.Client
	config    *rest.Config
}

// SimplePodContext can create and delete pods.
type SimplePodContext struct {
	client client.Client
	config *rest.Config
	// PodLabels are labels to be added to the created pods
	PodLabels map[string]string
	// IntervalWait is the time between wait API calls.
	IntervalWait time.Duration
	// TimeoutWait is the time waited for a pod to reach Running state or be deleted.
	TimeoutWait time.Duration
}

// NewSimplePodContext creates a new SimplePodContext.
func NewSimplePodContext(client client.Client, config *rest.Config, podLabels map[string]string) (*SimplePodContext, error) {
	return &SimplePodContext{
		client:       client,
		config:       config,
		PodLabels:    podLabels,
		IntervalWait: 2 * time.Second,
		TimeoutWait:  time.Minute,
	}, nil
}

// Create creates a Pod and waits for it to get in Running state.
func (spc *SimplePodContext) Create(ctx context.Context, podConstructorFn func() *corev1.Pod) (PodExecutor, error) {
	pod := podConstructorFn()
	for label, value := range spc.PodLabels {
		if _, ok := pod.Labels[label]; !ok {
			pod.Labels[label] = value
		}
	}

	if err := spc.client.Create(ctx, pod); err != nil {
		return nil, err
	}

	name := pod.Name
	namespace := pod.Namespace

	if err := spc.waitPodHealthy(ctx, name, namespace); err != nil {
		return nil, err
	}

	return NewPodExecutor(spc.client, spc.config, name, namespace)
}

// Delete deletes a specific pod and waits for it to be deleted.
func (spc *SimplePodContext) Delete(ctx context.Context, name, namespace string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	if err := spc.client.Delete(ctx, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return spc.waitPodDeleted(ctx, name, namespace)
}

// NewPodExecutor creates a new SimplePodExecutor.
func NewPodExecutor(client client.Client, config *rest.Config, name, namespace string) (*SimplePodExecutor, error) {
	return &SimplePodExecutor{
		name:      name,
		namespace: namespace,
		client:    client,
		config:    config,
	}, nil
}

// Execute runs a command is a pod.
func (spe *SimplePodExecutor) Execute(ctx context.Context, command string, commandArg string) (string, error) {
	client, err := corev1client.NewForConfig(spe.config)
	if err != nil {
		return "", err
	}

	var stdout, stderr bytes.Buffer
	request := client.RESTClient().
		Post().
		Resource("pods").
		Name(spe.name).
		Namespace(spe.namespace).
		SubResource("exec").
		Param("container", "container").
		Param("command", command).
		Param("stdin", "true").
		Param("stdout", "true").
		Param("stderr", "true").
		Param("tty", "false")

	executor, err := remotecommand.NewSPDYExecutor(spe.config, http.MethodPost, request.URL())
	if err != nil {
		return "", fmt.Errorf("failed to initialized the command exector: %w", err)
	}

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  strings.NewReader(commandArg),
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	stderrByte, otherErr := io.ReadAll(&stderr)
	if err != nil && otherErr != nil {
		return "", errors.Join(err, otherErr)
	} else if otherErr != nil {
		return "", otherErr
	}

	if err != nil && len(stderrByte) > 0 {
		return "", fmt.Errorf("err: %w, command %s %s stderr output: %s", err, command, commandArg, string(stderrByte))
	} else if len(stderrByte) > 0 {
		return "", fmt.Errorf("command %s %s stderr output: %s", command, commandArg, string(stderrByte))
	}

	if err != nil {
		return "", fmt.Errorf("err: %w, command %s %s", err, command, commandArg)
	}

	result, err := io.ReadAll(&stdout)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func (spc *SimplePodContext) waitPodHealthy(ctx context.Context, name, namespace string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, spc.TimeoutWait)
	defer cancel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	return retry.Until(timeoutCtx, spc.IntervalWait, func(ctx context.Context) (done bool, err error) {
		if err := spc.client.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			return retry.SevereError(err)
		}

		if pod.Status.Phase != corev1.PodRunning {
			conditions, err := json.Marshal(pod.Status.Conditions)
			if err != nil {
				return retry.MinorError(fmt.Errorf("failed parsing pod %s status conditions: %w", client.ObjectKeyFromObject(pod).String(), err))
			}
			return retry.MinorError(fmt.Errorf("pod %s is not yet Running, pod conditions: %s", client.ObjectKeyFromObject(pod).String(), string(conditions)))
		}

		return retry.Ok()
	})
}

func (spc *SimplePodContext) waitPodDeleted(ctx context.Context, name, namespace string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, spc.TimeoutWait)
	defer cancel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	return retry.Until(timeoutCtx, spc.IntervalWait, func(ctx context.Context) (done bool, err error) {
		if err := spc.client.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			if apierrors.IsNotFound(err) {
				return retry.Ok()
			}

			return retry.SevereError(err)
		}

		return retry.MinorError(fmt.Errorf("pod %s is not yet deleted", client.ObjectKeyFromObject(pod).String()))
	})
}
