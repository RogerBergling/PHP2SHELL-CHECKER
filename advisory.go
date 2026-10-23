package main

const (
	cveUploadProgress       = "CVE-2026-115560"
	uploadProgressDirective = "session.upload_progress.enabled"
)

// Advisory is a security note that is tracked separately from the PHP2Shell
// version verdict. Remote checks cannot read php.ini, so the scanner reports
// what it can observe and what the administrator should verify.
type Advisory struct {
	CVE            string   `json:"cve"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	Label          string   `json:"label"`
	Detail         string   `json:"detail,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

// assessUploadProgress builds the CVE-2026-115560 advisory. PHP considers the
// issue unlikely and ships no emergency fix; the recommended mitigation is to
// disable session.upload_progress until the next routine PHP release.
//
// The advisory becomes stronger ("possible") when the page shows both PHP
// sessions and file uploads, because that is the configuration in which the
// feature can matter. It is still only an indicator: the actual php.ini value
// cannot be read over HTTP.
func assessUploadProgress(det detection) Advisory {
	advisory := Advisory{
		CVE:            cveUploadProgress,
		Title:          "session.upload_progress",
		Severity:       "low",
		Status:         "review",
		Label:          "Kontrollera konfigurationen",
		Recommendation: "Stäng av funktionen i php.ini: " + uploadProgressDirective + " = Off. Starta om PHP-FPM/Apache. Ingen brådskande säkerhetsuppdatering finns; rättelsen väntas i nästa ordinarie PHP-utgåva.",
	}

	version := "PHP"
	if det.version != "" {
		version = "PHP " + det.version
	}

	var evidence []string
	if det.sessionCookie {
		evidence = append(evidence, "PHP-session används (sessionscookie hittades)")
	}
	if det.uploadForm {
		evidence = append(evidence, "Filuppladdning hittades i HTML-svaret")
	}
	advisory.Evidence = evidence

	if det.sessionCookie && det.uploadForm {
		advisory.Status = "possible"
		advisory.Label = "Möjligen påverkad – kontrollera"
		advisory.Detail = version + " använder både PHP-sessioner och filuppladdning. Det är en förutsättning för det ovanliga konfigurationsläge som CVE-2026-115560 kräver. PHP bedömer risken som låg och planerar ingen brådskande fix. Skannern kan inte läsa php.ini via HTTP – verifiera " + uploadProgressDirective + " på servern."
		return advisory
	}

	if det.version == "" {
		advisory.Detail = "PHP upptäcktes men versionen kunde inte fastställas. CVE-2026-115560 påverkar konfigurationer där " + uploadProgressDirective + " är aktiverat. PHP bedömer risken som låg och planerar ingen brådskande fix. Verifiera inställningen på servern."
		return advisory
	}

	advisory.Detail = version + " kan påverkas av CVE-2026-115560. Sårbarheten kräver en ovanlig konfiguration och PHP bedömer risken som låg; ingen brådskande fix utfärdas. Skannern kan inte läsa php.ini via HTTP. Kontrollera " + uploadProgressDirective + " på servern."
	return advisory
}
