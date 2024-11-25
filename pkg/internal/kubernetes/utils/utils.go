// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

// PodSecurityStandardProfile defines the different restriction levels that can be applied to the default operations of a PodSecurity admission plugin.
type PodSecurityStandardProfile string

const (
	// PSSProfilePrivileged indicates an unrestricted policy, which allows for known privilege escalations.
	PSSProfilePrivileged PodSecurityStandardProfile = "privileged"
	// PSSProfileBaseline indicates a minimally restrictive policy, which bars from privilege escalations.
	PSSProfileBaseline PodSecurityStandardProfile = "baseline"
	// PSSProfileRestricted indicates a heavily restrictive policy.
	PSSProfileRestricted PodSecurityStandardProfile = "restricted"
)

// Level defines the order of restrictiveness of the different PodSecurityStandardProfile values. Higher number indicates more restrictions.
func (profile PodSecurityStandardProfile) Level() int {
	switch profile {
	case PSSProfilePrivileged:
		return 1
	case PSSProfileBaseline:
		return 2
	case PSSProfileRestricted:
		return 3
	default:
		return -1
	}
}

// LessRestrictive is a comparator that checks if the calling profile is less restrictive than the argument profile that is evaluated.
func (profile PodSecurityStandardProfile) LessRestrictive(argumentProfile PodSecurityStandardProfile) bool {
	return profile.Level() < argumentProfile.Level()
}
