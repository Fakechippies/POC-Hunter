package cve

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
	"github.com/Fakechippies/pochunter/versioncanon"
)

type NVDSource struct{}

func (o NVDSource) Name() string { return "NVD" }

func (o NVDSource) Query(ctx context.Context, product, version string) ([]Finding, error) {
	targeted, err := o.queryByKeyword(ctx, product+" "+version)
	if err != nil {
		return nil, err
	}
	if len(targeted) > 0 {
		return targeted, nil
	}

	broad, err := o.queryByKeyword(ctx, product)
	if err != nil {
		return nil, err
	}

	filtered := filterByVersionVariants(broad, version)
	if len(filtered) > 0 {
		return filtered, nil
	}
	return broad, nil
}

func (o NVDSource) queryByKeyword(ctx context.Context, keyword string) ([]Finding, error) {
	URL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=2000",
		url.QueryEscape(strings.TrimSpace(keyword)),
	)
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	err := httpclient.JSON(ctx, "GET", URL, nil, nil, &nvdResp)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, vuln := range nvdResp.Vulnerabilities {
		var find Finding
		find.CVE = vuln.CVE.ID
		find.Source = o.Name()
		for _, d := range vuln.CVE.Descriptions {
			if d.Lang == "en" {
				find.Detail = d.Value
				break
			}
		}
		findings = append(findings, find)
	}

	return findings, nil
}

func filterByVersionVariants(findings []Finding, version string) []Finding {
	variants := versioncanon.Variants(version)
	if len(variants) == 0 {
		return findings
	}

	var filtered []Finding
	for _, finding := range findings {
		detail := strings.ToLower(finding.Detail)
		for _, variant := range variants {
			if strings.Contains(detail, strings.ToLower(variant)) {
				filtered = append(filtered, finding)
				break
			}
		}
	}
	return filtered
}
