package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
)

type VulnersSource struct {
	APIKey string
}

func (o *VulnersSource) Name() string { return "Vulners" }

func (o *VulnersSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	if o.APIKey == "" {
		return nil, fmt.Errorf("VULNERS_API_KEY not set")
	}

	cpeObj := map[string]interface{}{}
	if vendor != "" {
		cpeObj["vendor"] = vendor
	}
	if product != "" {
		cpeObj["product"] = product
	}
	if version != "" {
		cpeObj["version"] = version
	}

	if len(cpeObj) == 0 {
		return nil, fmt.Errorf("skipped (no vendor/product/version provided)")
	}

	body, err := json.Marshal(map[string]interface{}{
		"software": []interface{}{cpeObj},
		"match":    "partial",
		"catalog":  "extended",
		"fields":   []string{"title", "cvelist", "type"},
	})
	if err != nil {
		return nil, err
	}

	var auditResp struct {
		Result []struct {
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Title   string   `json:"title"`
				CVEList []string `json:"cvelist"`
			} `json:"vulnerabilities"`
		} `json:"result"`
	}

	if err := httpclient.JSON(ctx, "POST", "https://vulners.com/api/v4/audit/software",
		map[string]string{"X-Api-Key": o.APIKey, "Content-Type": "application/json"},
		body, &auditResp,
	); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, item := range auditResp.Result {
		for _, vuln := range item.Vulnerabilities {
			cve := strings.ToUpper(strings.TrimSpace(vuln.ID))
			if len(vuln.CVEList) > 0 {
				cve = strings.ToUpper(strings.TrimSpace(vuln.CVEList[0]))
			}
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			findings = append(findings, Finding{
				CVE:    cve,
				Source: o.Name(),
				Detail: vuln.Title,
			})
		}
	}

	return findings, nil
}
