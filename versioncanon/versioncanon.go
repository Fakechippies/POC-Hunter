package versioncanon

import "strings"

func Variants(version string) []string {
	v := normalizeVersion(version)
	if v == "" {
		return nil
	}

	parts := strings.Split(v, ".")
	set := map[string]struct{}{
		v:              {},
		"v" + v:        {},
		v + ".x":       {},
		"v" + v + ".x": {},
	}

	if len(parts) >= 2 {
		majorMinor := parts[0] + "." + parts[1]
		set[majorMinor] = struct{}{}
		set["v"+majorMinor] = struct{}{}
		set[majorMinor+".x"] = struct{}{}
		set["v"+majorMinor+".x"] = struct{}{}
	}

	var variants []string
	for token := range set {
		variants = append(variants, token)
	}
	return variants
}

func normalizeVersion(version string) string {
	v := strings.ToLower(strings.TrimSpace(version))
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return ""
	}

	parts := strings.Split(v, ".")
	if len(parts) == 0 {
		return ""
	}

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			parts[i] = "0"
			continue
		}
		trimmed := strings.TrimLeft(part, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		parts[i] = trimmed
	}

	return strings.Join(parts, ".")
}
