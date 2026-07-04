package cve

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
)

type GithubSource struct {
	APIKey string
}

func (o GithubSource) Name() string { return "github-advisories" }

func (o GithubSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	if o.APIKey == "" {
		return nil, fmt.Errorf("Github API required")

	}

	if ecosystem == "" {
		return nil, fmt.Errorf("Github Advisory requires ecosystem to be entered")
	}

	ghEcosystem, ok := normalizeGithubEcosystem(ecosystem)
	if !ok {
		return nil, fmt.Errorf("unsupported github ecosystem %q", ecosystem)
	}

	requestURL := fmt.Sprintf("https://api.github.com/advisories?ecosystem=%s&affects=%s&sort=published&direction=desc&per_page=100",
		url.QueryEscape(ghEcosystem),
		url.QueryEscape(product),
	)

	var githubAdvResp []struct {
		CVE     string `json:"cve_id"`
		Summary string `json:"summary"`
	}

	if err := httpclient.JSON(ctx, "GET", requestURL,
		map[string]string{"Content-Type": "application/vnd.github+json", "Authorization": "Bearer " + o.APIKey},
		nil, &githubAdvResp,
	); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, g := range githubAdvResp {
		findings = append(findings, Finding{CVE: g.CVE, Source: o.Name(), Detail: g.Summary})
	}
	return findings, nil
}

func normalizeGithubEcosystem(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "rubygems":
		return "rubygems", true
	case "npm":
		return "npm", true
	case "pip", "pypi":
		return "pip", true
	case "maven":
		return "maven", true
	case "nuget":
		return "nuget", true
	case "composer":
		return "composer", true
	case "go", "golang":
		return "go", true
	case "rust", "crates.io":
		return "rust", true
	case "erlang":
		return "erlang", true
	case "actions", "github-actions":
		return "actions", true
	case "pub":
		return "pub", true
	case "swift":
		return "swift", true
	case "other":
		return "other", true
	default:
		return "", false
	}
}
