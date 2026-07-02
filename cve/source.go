package cve

import "context"

type Finding struct {
	CVE    string
	Source string
	Detail string
}

type Source interface {
	Query(ctx context.Context, product, version string) ([]Finding, error)
	Name() string
}
