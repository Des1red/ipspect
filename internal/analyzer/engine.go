package analyzer

import (
	"ipspect/internal/analyzer/identify"
	"ipspect/internal/analyzer/recog"
	"ipspect/internal/analyzer/result/fingerprint"
	"ipspect/internal/analyzer/result/resolution"
	"ipspect/internal/database/load"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"net/http"
)

type Engine struct {
	session recog.Session
}

func New() *Engine {
	return &Engine{}
}

// Identification

func (e *Engine) IdentifyCaptured(
	detail *models.PortDetail,
) (
	models.FingerprintMatch,
	models.FingerprintMatch,
) {
	passive := identify.DetectBanner(detail)

	recognized := e.session.RecognizePassive(
		models.NewRecogEvidence(detail),
	)

	if recognized.Service != "" {
		recognized = fingerprint.PreservePassiveConfidence(
			recognized,
			passive,
		)
	}

	return passive, recognized
}

func (e *Engine) IsBinaryResponse(
	data []byte,
) bool {
	return identify.IsBinaryResponse(data)
}

func (e *Engine) DescribeUnknown(
	data []byte,
) string {
	return identify.DescribeUnknown(data)
}

func (e *Engine) IdentifyDNSResponse(
	response []byte,
	transactionID [2]byte,
	question []byte,
) (models.FingerprintMatch, bool) {
	return identify.IdentifyDNSResponse(
		response,
		transactionID,
		question,
	)
}

func (e *Engine) IdentifyHTTPResponse(
	response *http.Response,
	secure bool,
) models.FingerprintMatch {
	return identify.IdentifyHTTPResponse(
		response,
		secure,
	)
}

func (e *Engine) IsHTTPSOnlyDiagnostic(
	body []byte,
) bool {
	return identify.IsHTTPSOnlyDiagnostic(body)
}

func (e *Engine) LookupVendor(
	mac string,
) string {
	return load.LookupVendor(mac)
}

func (e *Engine) LookupPort(
	port int,
) string {
	return load.LookupPort(port)
}

func (e *Engine) IdentifyNetBIOSResponse(
	data []byte,
	id uint16,
) string {
	return identify.IdentifyNetBIOSResponse(
		data,
		id,
	)
}

// Fingerprinting

func (e *Engine) AnalyzeBinary(
	detail *models.PortDetail,
	response []byte,
	probe *requests.Probe,
) models.FingerprintMatch {
	return fingerprint.AnalyzeBinary(
		detail,
		response,
		probe,
		&e.session,
	)
}

func (e *Engine) AnalyzeRawResponse(
	detail *models.PortDetail,
	response []byte,
	probe *requests.Probe,
) (models.FingerprintMatch, bool) {
	return fingerprint.AnalyzeRawResponse(
		detail,
		response,
		probe,
		&e.session,
	)
}

func (e *Engine) RecordMatches(
	detail *models.PortDetail,
	matches []models.FingerprintMatch,
) {
	fingerprint.RecordMatches(
		detail,
		matches,
		&e.session,
	)
}

func (e *Engine) EnrichCapturedEvidence(
	detail *models.PortDetail,
) {
	fingerprint.EnrichCapturedEvidence(
		detail,
		&e.session,
	)
}

// Resolution

func (e *Engine) ResolveService(
	detail *models.PortDetail,
) {
	resolution.ResolveService(detail)
}

// probes
type Probe = requests.Probe

func (e *Engine) SelectProbes(
	search models.NucleiSearch,
) []Probe {
	return requests.ForEvidence(search)
}
