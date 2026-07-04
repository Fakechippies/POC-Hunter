package poc

import "context"

type Finding struct {
	CVE      string
	POC      string
	PushedAt string
	Owner    string
	Source   string
}

type Source interface {
	Query(ctx context.Context, CVE string) ([]Finding, error) // CVE format: CVE-20XX-10XXX, separated with dashes (-)
	Name() string
}
