package protocol

const (
	BaselineMaxRequestBytes   = 4 << 10
	BaselineMaxRequestRecords = 4
	LargeMaxRequestBytes      = 5 << 20
	// One header record, up to 320 body records, and two TLS handshake records.
	LargeMaxRequestRecords           = 323
	BaselineMaxResponseBytes         = 16 << 20
	BaselineMaxResponseRecordsOnline = 6
)
