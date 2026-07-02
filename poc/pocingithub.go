package poc

import (
	"context"

	"github.com/Fakechippies/pochunter/httpclient"
)

type POCInGithub struct{}

func (o POCInGithub) Name() string { return "poc-in-github" }

func (o POCInGithub) Query(ctx context.Context, CVE string) ([]Finding, error) {
	baseURL := "https://poc-in-github.motikan2010.net/api/v1/?cve_id="
	URL := baseURL + CVE

	type poc struct {
		Owner    string `json:"owner"`
		POCURL   string `json:"html_url"`
		PushedAt string `json:"pushed_at"`
	}

	var response struct {
		POCs []poc `json:"pocs"`
	}

	err := httpclient.JSON(ctx, "GET", URL, nil, nil, &response)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, poc := range response.POCs {
		var find Finding
		find.CVE = CVE
		find.Owner = poc.Owner
		find.POC = poc.POCURL
		find.PushedAt = poc.PushedAt

		findings = append(findings, find)
	}

	return findings, nil
}
