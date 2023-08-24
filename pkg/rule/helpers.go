// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule

// SingleCheckResult returns a [RuleResult] containing a single check.
func SingleCheckResult(r Rule, checkResult CheckResult) RuleResult {
	return RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: []CheckResult{checkResult},
	}
}

// PassedCheckResult returns a [CheckResult] with Passed status and the given message and target
func PassedCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Passed,
		Message: message,
		Target:  target,
	}
}

// FailedCheckResult returns a [CheckResult] with Failed status and the given message and target
func FailedCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Failed,
		Message: message,
		Target:  target,
	}
}

// WarningCheckResult returns a [CheckResult] with Warning status and the given message and target
func WarningCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Warning,
		Message: message,
		Target:  target,
	}
}

// ErroredCheckResult returns a [CheckResult] with Errored status and the given message and target
func ErroredCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Errored,
		Message: message,
		Target:  target,
	}
}

// NotImplementedCheckResult returns a [CheckResult] with v status and the given message and target
func NotImplementedCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  NotImplemented,
		Message: message,
		Target:  target,
	}
}

// SkippedCheckResult returns a [CheckResult] with Skipped status and the given message and target
func SkippedCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Skipped,
		Message: message,
		Target:  target,
	}
}

// AcceptedCheckResult returns a [CheckResult] with Accepted status and the given message and target
func AcceptedCheckResult(message string, target Target) CheckResult {
	return CheckResult{
		Status:  Accepted,
		Message: message,
		Target:  target,
	}
}
