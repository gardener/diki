package disak8sstig

// OptionsFiles contains files specific stat options
type OptionsFiles struct {
	ExpectedFileOwner ExpectedFileOwner `yaml:"expectedFileOwner"`
}

// ExpectedFileOwner contains expected user and group owners
type ExpectedFileOwner struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}
