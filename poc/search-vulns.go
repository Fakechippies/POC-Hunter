package poc

import (
	"context"
	"fmt"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
)

type SearchVulns struct {
	APIKey string
}

func (o SearchVulns) Name() string { return "search-vulns" }

func (o SearchVulns) Query(ctx context.Context, CVE string) ([]Finding, error) {
	if o.APIKey == "" {
		return nil, fmt.Errorf("API key needed for search-vulns.com")
		// Not standarized; use: SEARCHVULNS_API_KEY
	}

	URL := "https://search-vulns.com/api/search-vulns?query=" + CVE

	var searchVulnResp struct {
		Vulns map[string]struct {
			Exploits []string `json:"exploits"`
		} `json:"vulns"`
	}

	if err := httpclient.JSON(ctx, "GET", URL, map[string]string{"API-Key": o.APIKey}, nil, &searchVulnResp); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, v := range searchVulnResp.Vulns {
		for _, poc := range v.Exploits {
			findings = append(findings, Finding{CVE: CVE, Owner: extractOwner(poc), POC: poc, PushedAt: "-", Source: "search-vulns"})
		}
	}

	return findings, nil
}

func extractOwner(link string) string {
	s := strings.TrimPrefix(link, "https://")
	s = strings.TrimPrefix(s, "http://")

	parts := strings.Split(s, "/")
	// parts[0] == host, e.g, "github.com"
	host := parts[0]

	switch host {
	case "github.com", "gitee.com", "gitlab.com", "bitbucket.org":
		if len(parts) >= 2 {
			return parts[1]
		}
		return host
	default:
		return host
	}
}
