// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package junitreportparser

const (
	securityIDKey = "security_id"
	docstringKey  = "docstring"
)

// junitTestProperty models a <failure>, <error> or <skipped> element of a JUnit testcase.
type junitTestProperty struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// junitPropertyElement models a single <property> element of a JUnit testcase.
type junitPropertyElement struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// junitProperties models the <properties> element of a JUnit testcase.
type junitProperties struct {
	Properties []junitPropertyElement `xml:"property"`
}

// junitTestCase models a <testcase> element of a JUnit report.
type junitTestCase struct {
	ClassName  string             `xml:"classname,attr"`
	Name       string             `xml:"name,attr"`
	Failure    *junitTestProperty `xml:"failure"`
	Error      *junitTestProperty `xml:"error"`
	Skipped    *junitTestProperty `xml:"skipped"`
	Properties *junitProperties   `xml:"properties"`
}

// junitTestSuite models a <testsuite> element of a JUnit report.
type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

// junitTestSuites models the root <testsuites> element of a JUnit report.
type junitTestSuites struct {
	Name   string           `xml:"name,attr"`
	Suites []junitTestSuite `xml:"testsuite"`
}
