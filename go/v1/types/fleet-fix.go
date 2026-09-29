// Code generated from traust-contracts v0.44.0. DO NOT EDIT.

package types

import (
	"github.com/traust-security/traust-sdk/go/v1/enums"
)

type FleetFix struct {
	Description string              `json:"description"`
	Guards      FleetFixGuards      `json:"guards"`
	Id          string              `json:"id"`
	Matcher     FleetFixMatcher     `json:"matcher"`
	PatternRef  string              `json:"pattern_ref"`
	Resolver    *FleetFixResolver   `json:"resolver,omitempty"`
	Rewrite     FleetFixRewrite     `json:"rewrite"`
	Tests       []FleetFixTestsItem `json:"tests"`
}

type FleetFixGuards struct {
	MaxFilesChanged  *int  `json:"max_files_changed,omitempty"`
	RequireCleanTree *bool `json:"require_clean_tree,omitempty"`
}

type FleetFixMatcher struct {
	ContextRegex  *string                   `json:"context_regex,omitempty"`
	ContextWindow *int                      `json:"context_window,omitempty"`
	FileGlob      []string                  `json:"file_glob"`
	Kind          enums.FleetFixMatcherKind `json:"kind"`
	Lang          *string                   `json:"lang,omitempty"`
	MatchRegex    *string                   `json:"match_regex,omitempty"`
	Pattern       *string                   `json:"pattern,omitempty"`
	UrlRegex      *string                   `json:"url_regex,omitempty"`
	UrlWindow     *int                      `json:"url_window,omitempty"`
}

type FleetFixResolver struct {
	Kind *string `json:"kind,omitempty"`
	Ref  *string `json:"ref,omitempty"`
}

type FleetFixRewrite struct {
	Template string `json:"template"`
}

type FleetFixTestsItem struct {
	AfterContains    []string `json:"after_contains"`
	AfterNotContains []string `json:"after_not_contains,omitempty"`
	Before           string   `json:"before"`
	File             string   `json:"file"`
	Name             string   `json:"name"`
}
