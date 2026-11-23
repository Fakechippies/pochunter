package cve

import "context"

// Finding is one CVE search result. Reason explains why the finding matched
// the query (e.g. cpe_version, version_in_range, cpe_product, description);
// it is set by sources that perform structured matching.
type Finding struct {
	CVE    string
	Source string
	Detail string
	Score  float64
	Reason string
}

type Source interface {
	Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error)
	Name() string
}
