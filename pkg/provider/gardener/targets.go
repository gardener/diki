// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// StringTarget describes the targets which were checked during ruleset runs.
type StringTarget string

// String implements Stringer.
func (s StringTarget) String() string {
	return string(s)
}

// Target is a structure that can be represented as string.
// It is used to describe the targets which were checked during ruleset runs.
type Target map[string]string

// Target implements Stringer.
func (t Target) String() string {
	var sb strings.Builder
	sb.WriteString("[")

	sortedKeys := []string{}
	for key := range t {
		sortedKeys = append(sortedKeys, key)
	}
	slices.Sort(sortedKeys)

	for _, key := range sortedKeys {
		sb.WriteString(fmt.Sprintf(" %s:%s", key, t[key]))
	}

	sb.WriteString(" ]")
	return sb.String()
}

// NewTarget creates a new Target with the given key values.
// Panics if the number of arguments is an odd number.
func NewTarget(keyValuePairs ...string) Target {
	if len(keyValuePairs)%2 != 0 {
		panic("NewTarget: odd number of arguments")
	}
	t := Target{}

	for i := 0; i < len(keyValuePairs); i += 2 {
		t[keyValuePairs[i]] = keyValuePairs[i+1]
	}

	return t
}

// With creates a new Target with additional key values.
// It does not modify the original one.
// Panics if the number of arguments is an odd number.
func (t Target) With(keyValuePairs ...string) Target {
	if len(keyValuePairs)%2 != 0 {
		panic("With: odd number of arguments")
	}

	newTarget := maps.Clone(t)
	for i := 0; i < len(keyValuePairs); i += 2 {
		newTarget[keyValuePairs[i]] = keyValuePairs[i+1]
	}
	return newTarget
}
