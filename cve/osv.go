package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
)

type OSVSource struct{}

func (o OSVSource) Name() string { return "OSV" }

func (o OSVSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	if ecosystem == "" {
		return nil, fmt.Errorf("skipped (no -ecosystem given, OSV is package-ecosystem based)")
	}

	url := "https://api.osv.dev/v1/query"

	var osvResp struct {
		Vulns []struct {
			ID      string   `json:"id"`
			Aliases []string `json:"aliases"`
			Summary string   `json:"summary"`
		} `json:"vulns"`
	}

	body, _ := json.Marshal(map[string]interface{}{
		"version": version,
		"package": map[string]string{
			"name":      product,
			"ecosystem": ecosystem,
		},
	})

	if err := httpclient.JSON(ctx, "POST", url,
		map[string]string{"Content-Type": "application/json"},
		body, &osvResp,
	); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, vuln := range osvResp.Vulns {
		cve := vuln.ID
		for _, a := range vuln.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				cve = a
				break
			}
		}
		findings = append(findings, Finding{CVE: cve, Source: o.Name(), Detail: vuln.Summary})
	}
	return findings, nil
}
