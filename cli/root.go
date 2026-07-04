package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/Fakechippies/pochunter/cve"
	"github.com/Fakechippies/pochunter/poc"
	"github.com/spf13/cobra"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

type options struct {
	pocMode    bool
	searchMode bool
	vendor     string
	app        string
	version    string
	ecosystem  string
	sources    []string
	timeout    time.Duration
}

func Execute() error {
	opts := options{}

	rootCmd := &cobra.Command{
		Use:   "pochunter [query words]",
		Short: "Hunt CVEs and related public POCs",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args, opts)
		},
	}

	rootCmd.Flags().BoolVar(&opts.pocMode, "poc", false, "direct POC mode (treat input as CVE id)")
	rootCmd.Flags().BoolVar(&opts.searchMode, "search", false, "keyword search mode")
	rootCmd.Flags().StringVar(&opts.vendor, "vendor", "", "vendor name")
	rootCmd.Flags().StringVar(&opts.app, "app", "", "application/product name")
	rootCmd.Flags().StringVar(&opts.version, "version", "", "application version")
	rootCmd.Flags().StringVar(&opts.ecosystem, "ecosystem", "", "package ecosystem (for sources that use it)")
	rootCmd.Flags().StringSliceVar(&opts.sources, "sources", nil, "CVE sources to use (comma-separated: nvd,circl,osv,vulners,github)")
	rootCmd.Flags().DurationVar(&opts.timeout, "timeout", 30*time.Second, "request timeout")

	rootCmd.SetArgs(normalizeCompatFlags(os.Args[1:]))
	return rootCmd.Execute()
}

func normalizeCompatFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--" {
			continue
		}
		if arg == "-poc" {
			out = append(out, "--poc")
			continue
		}
		out = append(out, arg)
	}
	return out
}

func run(args []string, opts options) error {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	cveSources := buildCVESourcesFromEnv(opts.sources)
	pocSources := buildPOCSources()

	if opts.pocMode {
		if len(args) == 0 {
			return fmt.Errorf("poc mode expects a CVE id, e.g. -poc CVE-2026-38526")
		}
		cveID := normalizeCVE(args)
		progressf("POC mode enabled for %s", cveID)
		runPOCSources(ctx, pocSources, cveID)
		return nil
	}

	vendor, product, version, ecosystem, err := resolveSearchInput(args, opts)
	if err != nil {
		return err
	}

	progressf("Searching CVEs for vendor=%q product=%q version=%q ecosystem=%q", vendor, product, version, ecosystem)

	cveResults := collectCVEs(ctx, cveSources, vendor, product, version, ecosystem)
	allCVEFindings, uniqueCVEs := dedupeCVEs(cveResults)
	if len(allCVEFindings) == 0 {
		printCVESourceErrors(cveResults)
		warnf("No CVEs found for query")
		return nil
	}

	printCVEFindings("CVE Discovery", allCVEFindings)
	successf("Unique CVEs: %d", len(uniqueCVEs))
	printCVESourceErrors(cveResults)

	progressf("Searching POCs for %d CVEs", len(uniqueCVEs))
	pocResults := collectPOCsForCVEs(ctx, pocSources, uniqueCVEs)
	printPOCErrors(pocResults)
	allPOCs := flattenPOCResults(pocResults)
	if len(allPOCs) == 0 {
		warnf("No POCs found across discovered CVEs")
		return nil
	}

	printPOCFindings("POC Discovery", allPOCs)
	return nil
}

type cveSourceResult struct {
	source   string
	findings []cve.Finding
	err      error
}

type pocResult struct {
	cveID    string
	findings []poc.Finding
	err      error
}

func buildCVESourcesFromEnv(want []string) []cve.Source {
	all := map[string]cve.Source{
		"nvd":    cve.NVDSource{},
		"circl":  cve.CIRCLSource{},
		"osv":    cve.OSVSource{},
		"vulners": nil,
		"github":  nil,
	}
	if key := strings.TrimSpace(os.Getenv("VULNERS_API_KEY")); key != "" {
		all["vulners"] = &cve.VulnersSource{APIKey: key}
	}
	if key := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); key != "" {
		all["github"] = cve.GithubSource{APIKey: key}
	}

	filter := make(map[string]bool, len(want))
	for _, name := range want {
		filter[strings.ToLower(strings.TrimSpace(name))] = true
	}

	var sources []cve.Source
	for key, src := range all {
		if src == nil {
			continue
		}
		if len(filter) > 0 && !filter[key] {
			continue
		}
		sources = append(sources, src)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name() < sources[j].Name() })
	return sources
}

func buildPOCSources() []poc.Source {
	var sources []poc.Source
	sources = append(sources, poc.POCInGithub{})
	if key := strings.TrimSpace(os.Getenv("SEARCHVULNS_API_KEY")); key != "" {
		sources = append(sources, poc.SearchVulns{APIKey: key})
	}
	return sources
}

func collectCVEs(ctx context.Context, sources []cve.Source, vendor, product, version, ecosystem string) []cveSourceResult {
	results := make(chan cveSourceResult, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, err := source.Query(ctx, vendor, product, version, ecosystem)
			results <- cveSourceResult{source: source.Name(), findings: findings, err: err}
		}()
	}

	wg.Wait()
	close(results)

	out := make([]cveSourceResult, 0, len(sources))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].source < out[j].source })
	return out
}

func dedupeCVEs(results []cveSourceResult) ([]cve.Finding, []string) {
	var all []cve.Finding
	seenRow := map[string]struct{}{}
	seenCVE := map[string]struct{}{}
	var cveIDs []string

	for _, result := range results {
		for _, finding := range result.findings {
			key := finding.CVE + "|" + finding.Source + "|" + finding.Detail
			if _, ok := seenRow[key]; ok {
				continue
			}
			seenRow[key] = struct{}{}
			all = append(all, finding)

			if _, ok := seenCVE[finding.CVE]; !ok {
				seenCVE[finding.CVE] = struct{}{}
				cveIDs = append(cveIDs, finding.CVE)
			}
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].CVE == all[j].CVE {
			return all[i].Source < all[j].Source
		}
		return all[i].CVE < all[j].CVE
	})
	sort.Strings(cveIDs)
	return all, cveIDs
}

func collectPOCsForCVEs(ctx context.Context, sources []poc.Source, cveIDs []string) []pocResult {
	const maxWorkers = 8
	sem := make(chan struct{}, maxWorkers)
	results := make(chan pocResult, len(cveIDs))
	var wg sync.WaitGroup

	for _, cveID := range cveIDs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			findings, err := queryPOCsForCVE(ctx, sources, cveID)
			results <- pocResult{cveID: cveID, findings: findings, err: err}
		}()
	}

	wg.Wait()
	close(results)

	out := make([]pocResult, 0, len(cveIDs))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cveID < out[j].cveID })
	return out
}

func queryPOCsForCVE(ctx context.Context, sources []poc.Source, cveID string) ([]poc.Finding, error) {
	results := make(chan pocSourceResult, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func(s poc.Source) {
			defer wg.Done()
			findings, err := s.Query(ctx, cveID)
			results <- pocSourceResult{name: s.Name(), findings: findings, err: err}
		}(source)
	}

	wg.Wait()
	close(results)

	var all []poc.Finding
	for result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("%s: %w", result.name, result.err)
		}
		all = append(all, result.findings...)
	}
	return all, nil
}

func flattenPOCResults(results []pocResult) []poc.Finding {
	var all []poc.Finding
	for _, result := range results {
		all = append(all, result.findings...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CVE == all[j].CVE {
			if all[i].Owner == all[j].Owner {
				return all[i].POC < all[j].POC
			}
			return all[i].Owner < all[j].Owner
		}
		return all[i].CVE < all[j].CVE
	})
	return all
}

func printPOCErrors(results []pocResult) {
	for _, result := range results {
		if result.err != nil {
			warnf("%s: %v", result.cveID, result.err)
		}
	}
}

func printCVESourceErrors(results []cveSourceResult) {
	for _, result := range results {
		if result.err != nil {
			warnf("%s: %v", result.source, result.err)
		}
	}
}

func resolveSearchInput(args []string, opts options) (string, string, string, string, error) {
	vendor := strings.TrimSpace(opts.vendor)
	ecosystem := strings.TrimSpace(opts.ecosystem)

	if opts.app != "" {
		tokens := []string{opts.app}
		tokens = append(tokens, args...)

		if opts.version != "" {
			return vendor, strings.Join(tokens, " "), opts.version, ecosystem, nil
		}
		if len(tokens) < 2 {
			return "", "", "", "", fmt.Errorf("--app mode expects version in --version or as the last argument")
		}

		product := strings.Join(tokens[:len(tokens)-1], " ")
		version := tokens[len(tokens)-1]
		return vendor, product, version, ecosystem, nil
	}

	if opts.version != "" {
		if len(args) == 0 {
			return "", "", "", "", fmt.Errorf("--version requires product query words or --app")
		}
		return vendor, strings.Join(args, " "), opts.version, ecosystem, nil
	}

	if opts.searchMode || len(args) > 0 {
		if len(args) < 2 {
			return "", "", "", "", fmt.Errorf("keyword mode expects: --search <product words...> <version>")
		}
		product := strings.Join(args[:len(args)-1], " ")
		version := args[len(args)-1]
		return vendor, product, version, ecosystem, nil
	}

	return "", "", "", "", fmt.Errorf("provide search input via --search <product words...> <version> or --app <name> --version <version>")
}

type pocSourceResult struct {
	name     string
	findings []poc.Finding
	err      error
}

func runPOCSources(ctx context.Context, sources []poc.Source, cveID string) {
	results := make(chan pocSourceResult, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func(s poc.Source) {
			defer wg.Done()
			findings, err := s.Query(ctx, cveID)
			results <- pocSourceResult{name: s.Name(), findings: findings, err: err}
		}(source)
	}

	wg.Wait()
	close(results)

	foundAny := false
	for result := range results {
		if result.err != nil {
			errorf("%s: %v", result.name, result.err)
			continue
		}
		if len(result.findings) == 0 {
			continue
		}
		foundAny = true
		printPOCFindings(result.name, result.findings)
	}
	if !foundAny {
		warnf("%s: no POCs found", cveID)
	}
}

func normalizeCVE(args []string) string {
	return strings.ToUpper(strings.Join(args, "-"))
}

func printCVEFindings(source string, findings []cve.Finding) {
	if len(findings) == 0 {
		warnf("%s: no CVEs found", source)
		return
	}

	successf("%s: %d findings", source, len(findings))

	cveW := len("CVE")
	srcW := len("SOURCE")
	for _, f := range findings {
		if len(f.CVE) > cveW {
			cveW = len(f.CVE)
		}
		if len(f.Source) > srcW {
			srcW = len(f.Source)
		}
	}
	gap := 2
	detailW := terminalWidth() - cveW - srcW - gap*2
	if detailW < 20 {
		detailW = 20
	}

	fmt.Printf("%-*s%*s  %s\n", cveW, "CVE", srcW+gap, "SOURCE", "DETAIL")
	fmt.Printf("%s%s  %s\n", strings.Repeat("-", cveW), strings.Repeat("-", srcW+gap), strings.Repeat("-", detailW))

	for _, f := range findings {
		detail := strings.ReplaceAll(f.Detail, "\n", " ")
		detail = strings.ReplaceAll(detail, "\r", "")
		lines := wrapText(detail, detailW)
		for i, line := range lines {
			if i == 0 {
				fmt.Printf("%-*s%*s  %s\n", cveW, f.CVE, srcW+gap, f.Source, line)
			} else {
				fmt.Printf("%-*s%*s  %s\n", cveW, "", srcW+gap, "", line)
			}
		}
	}
}

func printPOCFindings(source string, findings []poc.Finding) {
	successf("%s: %d POCs", source, len(findings))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tSOURCE\tOWNER\tPUSHED AT\tPOC")
	for _, finding := range findings {
		src := finding.Source
		if src == "" {
			src = source
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", finding.CVE, src, finding.Owner, finding.PushedAt, finding.POC)
	}
	_ = w.Flush()
}

func progressf(format string, args ...interface{}) {
	fmt.Printf("%s[*]%s %s\n", colorCyan, colorReset, fmt.Sprintf(format, args...))
}

func successf(format string, args ...interface{}) {
	fmt.Printf("%s[+]%s %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
}

func warnf(format string, args ...interface{}) {
	fmt.Printf("%s[-]%s %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
}

func errorf(format string, args ...interface{}) {
	fmt.Printf("%s[!]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

func terminalWidth() int {
	const defaultWidth = 80
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if w, err := strconv.Atoi(cols); err == nil && w > 0 {
			return w
		}
	}
	return defaultWidth
}

func wrapText(s string, width int) []string {
	if width <= 0 || s == "" {
		return []string{s}
	}
	var lines []string
	for _, word := range strings.Fields(s) {
		if len(lines) == 0 {
			lines = append(lines, word)
			continue
		}
		last := len(lines) - 1
		if len(lines[last])+1+len(word) > width {
			lines = append(lines, word)
		} else {
			lines[last] += " " + word
		}
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}
