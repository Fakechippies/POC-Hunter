package cve

import (
	"context"
	"fmt"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
)

type CIRCLSource struct{}

func (o CIRCLSource) Name() string { return "CIRCL" }

func (o CIRCLSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	if vendor == "" {
		vendor = product // fallback: some CIRCL endpoints tolerate vendor == product
	}

	url := fmt.Sprintf("https://cve.circl.lu/api/search/%s/%s", vendor, product)

	var circlResp struct {
		Results map[string][][]interface{} `json:"results"`
	}

	if err := httpclient.JSON(ctx, "GET", url, nil, nil, &circlResp); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var findings []Finding
	for _, entries := range circlResp.Results {
		for _, entry := range entries {
			if len(entry) == 0 {
				continue
			}
			id, ok := entry[0].(string)
			if !ok || id == "" {
				continue
			}
			cveID := strings.ToUpper(id)
			if _, ok := seen[cveID]; ok {
				continue
			}
			seen[cveID] = struct{}{}

			findings = append(findings, Finding{
				CVE:    cveID,
				Source: o.Name(),
				Detail: "Matched by CIRCL vendor/product search",
			})
		}
	}
	return findings, nil
}
