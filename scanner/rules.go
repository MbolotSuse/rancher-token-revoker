package scanner

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

var tokenRule = config.Rule{
	Description: "Rancher token",
	Regex:       regexp.MustCompile("[bcdfghjklmnpqrstvwxz2456789]{54}"),
	Tags:        []string{"token", "Rancher"},
	Keywords:    []string{},
	RuleID:      "Rancher token values",
}
