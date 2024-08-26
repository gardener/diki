// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package rules implements rules that are shared across providers
// and correspond to the latest supported ruleset version.
// These rules can be reused by an older supported ruleset versions
// in case a rule implementation did not change.
// Rule implementations that had changed in latest supported version
// but still need to be supported because of old ruleset versions
// should be separated in ruleset versioned specific package.
package rules
