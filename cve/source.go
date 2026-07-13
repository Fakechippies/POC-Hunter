package cve

import "context"

type Finding struct {
	CVE    string
	Source string
	Detail string
	Score  float64
}

type Source interface {
	Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error)
	Name() string
}
