<h1 align="center">arandu-io/storage</h1>

<p align="center">File storage for Arandu.</p>

<p align="center">
<a href="https://github.com/arandu-io/storage/actions/workflows/ci.yml"><img src="https://github.com/arandu-io/storage/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
<a href="https://pkg.go.dev/github.com/arandu-io/storage"><img src="https://pkg.go.dev/badge/github.com/arandu-io/storage.svg" alt="Go Reference"></a>
<a href="https://github.com/arandu-io/storage/tags"><img src="https://img.shields.io/github/v/tag/arandu-io/storage?label=version" alt="Latest Version"></a>
<a href="LICENSE.md"><img src="https://img.shields.io/github/license/arandu-io/storage" alt="License"></a>
</p>


## About the storage adapter

A local disk driver in the core, and S3-compatible object storage in its own
module, because Go has no optional dependency and the AWS SDK is not small.

```go
import _ "github.com/arandu-io/storage/s3"
```

Every path is prefixed by the tenant, taken from the `Grant`. A tenant cannot
name a path that reaches another tenant's namespace — the identifier is checked
against a closed pattern for exactly that reason.

Cloudflare R2 before AWS S3: same API, and the suggested default starts there.

## Learning Arandu

The API reference is generated from the doc comments and lives on
[pkg.go.dev](https://pkg.go.dev/github.com/arandu-io/framework). Every exported
symbol carries one, and that is deliberate: it is the documentation that cannot
drift from the code, because it sits in the same file.

The CLI documents itself. `aru help` lists every command, and each one explains
what it writes and what to do with it. `aru doctor` explains what it found and
what breaks, not which rule was violated.

A guide and a website do not exist yet, and that is a decision rather than a
gap: a guide written against an API that still moves is work done twice, and the
second time is worse — there is wrong documentation published. The site is the
next phase, and it will be an Arandu application.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Before opening a pull request, the three
commands at the top of that file have to pass, and CI runs exactly them.

## Security Vulnerabilities

Please review [our security policy](SECURITY.md) on how to report a
vulnerability. Never open a public issue for one.

## License

Open-sourced software licensed under the [MIT license](LICENSE.md).
