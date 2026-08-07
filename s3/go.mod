module github.com/arandu-io/storage/s3

go 1.25.0

// No SDK, and its own module anyway: a project storing on local disk should not
// carry the S3 protocol implementation, and a project on R2 should not carry a
// directory walker.
//
// The protocol is HTTP with a signature. SigV4 is two hundred lines against an
// AWS SDK that brings a hundred modules, its own credential chain, its own retry
// policy and its own context rules -- and the algorithm has not changed since
// 2012, while the SDK's surface changes every quarter.
require github.com/arandu-io/framework v0.13.2

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)
