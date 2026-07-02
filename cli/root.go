package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	app        string
	version    string
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
	rootCmd.Flags().StringVar(&opts.app, "app", "", "application/product name")
	rootCmd.Flags().StringVar(&opts.version, "version", "", "application version")
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

	cveSources := []cve.Source{cve.NVDSource{}}
	pocSources := []poc.Source{poc.POCInGithub{}}

	if opts.pocMode {
		if len(args) == 0 {
			return fmt.Errorf("poc mode expects a CVE id, e.g. -poc CVE-2026-38526")
		}
		cveID := normalizeCVE(args)
		progressf("POC mode enabled for %s", cveID)
		runPOCSources(ctx, pocSources, cveID)
		return nil
	}

	product, version, err := resolveSearchInput(args, opts)
	if err != nil {
		return err
	}

	progressf("Searching CVEs for %s %s", product, version)

	var allCVEs []cve.Finding
	seen := map[string]struct{}{}
	for _, source := range cveSources {
		findings, err := source.Query(ctx, product, version)
		if err != nil {
			errorf("%s query failed: %v", source.Name(), err)
			continue
		}
		printCVEFindings(source.Name(), findings)
		for _, finding := range findings {
			if _, ok := seen[finding.CVE]; ok {
				continue
			}
			seen[finding.CVE] = struct{}{}
			allCVEs = append(allCVEs, finding)
		}
	}

	if len(allCVEs) == 0 {
		warnf("No CVEs found for query")
		return nil
	}

	for _, finding := range allCVEs {
		progressf("Searching POCs for %s", finding.CVE)
		runPOCSources(ctx, pocSources, finding.CVE)
	}

	return nil
}

func resolveSearchInput(args []string, opts options) (string, string, error) {
	if opts.app != "" {
		tokens := []string{opts.app}
		tokens = append(tokens, args...)

		if opts.version != "" {
			return strings.Join(tokens, " "), opts.version, nil
		}
		if len(tokens) < 2 {
			return "", "", fmt.Errorf("--app mode expects version in --version or as the last argument")
		}

		product := strings.Join(tokens[:len(tokens)-1], " ")
		version := tokens[len(tokens)-1]
		return product, version, nil
	}

	if opts.version != "" {
		if len(args) == 0 {
			return "", "", fmt.Errorf("--version requires product query words or --app")
		}
		return strings.Join(args, " "), opts.version, nil
	}

	if opts.searchMode || len(args) > 0 {
		if len(args) < 2 {
			return "", "", fmt.Errorf("keyword mode expects: --search <product words...> <version>")
		}
		product := strings.Join(args[:len(args)-1], " ")
		version := args[len(args)-1]
		return product, version, nil
	}

	return "", "", fmt.Errorf("provide search input via --search <product words...> <version> or --app <name> --version <version>")
}

func runPOCSources(ctx context.Context, sources []poc.Source, cveID string) {
	foundAny := false
	for _, source := range sources {
		findings, err := source.Query(ctx, cveID)
		if err != nil {
			errorf("%s: %v", source.Name(), err)
			continue
		}
		if len(findings) == 0 {
			continue
		}
		foundAny = true
		printPOCFindings(source.Name(), findings)
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

	successf("%s: %d CVEs", source, len(findings))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tSOURCE\tDETAIL")
	for _, finding := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\n", finding.CVE, finding.Source, finding.Detail)
	}
	_ = w.Flush()
}

func printPOCFindings(source string, findings []poc.Finding) {
	successf("%s: %d POCs", source, len(findings))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tOWNER\tPUSHED AT\tPOC")
	for _, finding := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", finding.CVE, finding.Owner, finding.PushedAt, finding.POC)
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
