# storage

File storage for [Arandu](https://github.com/arandu-io/framework): local disk,
and object storage over the S3 protocol.

The contract lives in the core, in `framework/storage`. Every method takes a
`Grant`, and the path is prefixed by its tenant — a file is customer data, and
a path without a tenant is a leak with a directory name.

```sh
go get github.com/arandu-io/storage        # local disk
go get github.com/arandu-io/storage/s3     # object storage
```

## Cloudflare R2 is the default

```go
files, err := s3.R2(s3.R2Config{
    AccountID: cfg.R2AccountID,
    Bucket:    "uploads",
    AccessKey: cfg.R2AccessKey,
    SecretKey: cfg.R2SecretKey,
})
```

R2 charges **no egress**. For a SaaS that serves files back to the people who
uploaded them, egress is most of the bill on every other provider — and it is
the line that grows with success.

The package is named for the protocol, not the vendor, like `kv` is named for
RESP and not for Redis. The same implementation covers R2, Amazon S3,
DigitalOcean Spaces, Backblaze B2 and MinIO:

```go
files, err := s3.New(s3.Config{
    Endpoint: "https://s3.amazonaws.com", Bucket: "uploads",
    Region: "us-east-1", AccessKey: …, SecretKey: …,
})
```

Local disk, for development and for a single machine:

```go
files, err := storage.NewDisk("storage/files")
```

## What it is not

**There is no SDK.** The S3 protocol is HTTP with a signature, and SigV4 is two
hundred lines — against an AWS SDK that brings a hundred modules, its own
credential chain, its own retry policy and its own context rules. The algorithm
has not changed since 2012; the SDK's surface changes every quarter.

**There is no `storage:link`.** Laravel symlinks a directory into the public
root, which makes every stored file readable by URL and turns authorization
into hoping nobody guesses the name. Here a file is served by a route, and the
route runs a Policy like any other.

MIT. See [LICENSE.md](LICENSE.md).
