// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"slices"
)

// EqualSets checks if two slices contain exactly the same elements independent of the ordering.
func EqualSets(s1, s2 []string) bool {
	clone1 := slices.Clone(s1)
	clone2 := slices.Clone(s2)
	slices.Sort(clone1)
	slices.Sort(clone2)
	return slices.Equal(clone1, clone2)
}

// Subset checks if all elements of s1 are contained in s2. An empty s1 is always a subset of s2.
func Subset(s1, s2 []string) bool {
	for _, s1v := range s1 {
		if !slices.Contains(s2, s1v) {
			return false
		}
	}
	return true
}

// Subset checks if s1 and s2 intersect. Empty sets do not intersect.
func Intersect(s1, s2 []string) bool {
	for _, s1v := range s1 {
		if slices.Contains(s2, s1v) {
			return true
		}
	}
	return false
}

// StartsWith checks if all ordered elements of s2 are the first elements that occur in s1. If s2 is empty, the function returns true.
func StartsWith(s1 []string, s2 ...string) bool {
	if len(s2) > len(s1) {
		return false
	}

	for i := range s2 {
		if s2[i] != s1[i] {
			return false
		}
	}
	return true
}

// MatchLabels checks if all m2 keys and values are present in m1. If m1 or m2 is nil returns false.
func MatchLabels(m1, m2 map[string]string) bool {
	if m1 == nil || m2 == nil {
		return false
	}

	for k, v := range m2 {
		if m1[k] != v {
			return false
		}
	}

	return true
}
