package scanner

// Finding represents a single finding in a file
type Finding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// ScanResult represents the result of a security check
type ScanResult struct {
	Category string    `json:"category"`
	Severity string    `json:"severity"` // "ok" | "warn" | "danger"
	Message  string    `json:"message"`
	Findings []Finding `json:"findings"`
}
