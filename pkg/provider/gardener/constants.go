// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardener

const (
	// LabelInstanceID is used to group all pods created by a single ruleset.
	LabelInstanceID = "compliance.gardener.cloud/instanceID"

	// LabelComplianceRoleKey is used to label pods related to compliance operations in the cluster.
	LabelComplianceRoleKey = "compliance.gardener.cloud/role"

	// LabelComplianceRolePrivPod is used as the label value for LabelComplianceRoleKey indicating privileged diki pods.
	LabelComplianceRolePrivPod = "diki-privileged-pod"
)
