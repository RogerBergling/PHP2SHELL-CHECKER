package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fixedVersions contains the first PHP release in each supported branch that
// contains the fixes for CVE-2026-109618 and CVE-2026-109619.
var fixedVersions = map[string]string{
	"8.2": "8.2.35",
	"8.3": "8.3.36",
	"8.4": "8.4.27",
	"8.5": "8.5.12",
}

var (
	phpVersionPrefixRe    = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?`)
	phpPreReleaseSuffixRe = regexp.MustCompile(`(?i)^(?:\s*[-._+~]\s*)?(?:alpha|beta|rc|dev|snapshot|preview)\d*`)
)

func hasPreReleaseSuffix(version string) bool {
	version = strings.TrimSpace(version)
	m := phpVersionPrefixRe.FindStringSubmatch(version)
	if m == nil {
		return false
	}
	return phpPreReleaseSuffixRe.MatchString(version[len(m[0]):])
}

type phpVersion struct {
	major, minor, patch int
	hasPatch            bool
}

func parsePHPVersion(s string) (phpVersion, bool) {
	s = strings.TrimSpace(s)
	m := phpVersionPrefixRe.FindStringSubmatch(s)
	if m == nil {
		return phpVersion{}, false
	}
	if hasPreReleaseSuffix(s) {
		// A release candidate or development build is not the final fixed
		// release. Treat it as unknown rather than falsely safe.
		return phpVersion{}, false
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return phpVersion{}, false
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return phpVersion{}, false
	}
	var patch int
	hasPatch := m[3] != ""
	if hasPatch {
		patch, err = strconv.Atoi(m[3])
		if err != nil {
			return phpVersion{}, false
		}
	}
	return phpVersion{major: major, minor: minor, patch: patch, hasPatch: hasPatch}, true
}

func (v phpVersion) String() string {
	if v.hasPatch {
		return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	}
	return fmt.Sprintf("%d.%d", v.major, v.minor)
}

func (v phpVersion) lessThan(other phpVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

func (v phpVersion) branch() string {
	return fmt.Sprintf("%d.%d", v.major, v.minor)
}

type phpAssessment struct {
	Verdict string
	Label   string
	FixedIn string
	Detail  string
}

func assessPHPVersion(version string) phpAssessment {
	v, ok := parsePHPVersion(version)
	if !ok {
		detail := "PHP-versionen kunde inte tolkas. Kontrollera serverns PHP-version manuellt."
		if hasPreReleaseSuffix(version) {
			detail = "PHP-versionen är en förhandsversion eller utvecklingsversion (" + version + "). Den kan inte antas innehålla den slutliga säkerhetsrättelsen. Kontrollera serverns PHP-version manuellt."
		}
		return phpAssessment{
			Verdict: "php_unknown",
			Label:   "PHP – okänd version",
			Detail:  detail,
		}
	}

	// The vulnerable code was introduced in PHP 5.4.0.
	if v.major < 5 || (v.major == 5 && v.minor < 4) {
		return phpAssessment{
			Verdict: "safe",
			Label:   "PHP – inte påverkad",
			Detail:  "PHP2Shell påverkar PHP 5.4 och senare. Den här versionen är mycket gammal och saknar fortfarande säkerhetsuppdateringar.",
		}
	}

	// PHP 8.1 and older have no official fixed release. Distributions and
	// commercial vendors may publish backports that keep the version number.
	if v.major < 8 || (v.major == 8 && v.minor < 2) {
		return phpAssessment{
			Verdict: "vulnerable",
			Label:   "Sårbar – EOL",
			FixedIn: "Ingen officiell fix – backport krävs",
			Detail:  "PHP " + v.String() + " är end-of-life och saknar officiell binär rättelse för PHP2Shell. PHP-projektet har publicerat källbackporter för 7.4, 8.0 och 8.1; äldre grenar kräver leverantörsbackport. Kontrollera paketets changelog efter CVE-2026-109618.",
		}
	}

	fixed, supported := fixedVersions[v.branch()]
	if !supported {
		return phpAssessment{
			Verdict: "php_unknown",
			Label:   "PHP – okänd status",
			Detail:  "Det finns ingen känd fixinformation för PHP " + v.String() + " i PHP2Shell-advisorn. Kontrollera leverantörens information.",
		}
	}

	fv, _ := parsePHPVersion(fixed)
	if v.lessThan(fv) {
		detail := "PHP " + v.String() + " är äldre än " + fixed + " och påverkas av PHP2Shell (CVE-2026-109618 och CVE-2026-109619)."
		if !v.hasPatch {
			detail += " Exakt patchversion framgick inte; utgå från att den är sårbar."
		}
		return phpAssessment{
			Verdict: "vulnerable",
			Label:   "Sårbar",
			FixedIn: fixed,
			Detail:  detail + " Uppdatera till " + fixed + " eller senare.",
		}
	}

	return phpAssessment{
		Verdict: "safe",
		Label:   "PHP – åtgärdad",
		FixedIn: fixed,
		Detail:  "PHP " + v.String() + " är samma som eller nyare än den rättade versionen " + fixed + ".",
	}
}
