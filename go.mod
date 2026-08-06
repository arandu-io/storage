module github.com/arandu-io/storage

go 1.25

// No SDK. This is the disk store, which needs nothing installed and is the
// right one for development and for a single machine.
//
// Object storage is github.com/arandu-io/storage/s3, its own module, because in
// Go there is no optional dependency: carrying the AWS SDK here would put it in
// the go.sum of every project that only wanted a directory.
require github.com/arandu-io/framework v0.10.0

require (
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
