package verifier

type TrustInputFileEvidence struct {
	Path           string
	Device         uint64
	Inode          uint64
	UID            uint32
	Mode           uint32
	NLink          uint64
	SchemaFormat   string
	SnapshotDigest string
}
