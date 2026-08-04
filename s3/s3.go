// Package s3 is object storage over the S3 protocol.
//
// The package is named for the protocol rather than for a vendor, like kv is
// named for the protocol rather than for Redis. One implementation covers
// Cloudflare R2, Amazon S3, DigitalOcean Spaces, Backblaze B2 and MinIO,
// because they all speak it.
//
// # R2 is the default
//
// Use R2 unless something forces otherwise:
//
//	store, err := s3.R2(s3.R2Config{
//	    AccountID: cfg.R2AccountID,
//	    Bucket:    "uploads",
//	    AccessKey: cfg.R2AccessKey,
//	    SecretKey: cfg.R2SecretKey,
//	})
//
// It is the default for a reason that shows up on an invoice: R2 charges no
// egress. For a SaaS that serves files back to the people who uploaded them,
// egress is most of the bill on every other provider, and it is the line that
// grows with success.
//
// # What it is not
//
// There is no SDK here. The S3 protocol is HTTP with a signature, and SigV4 is
// two hundred lines -- against an AWS SDK that brings a hundred modules,
// its own credential chain, its own retry policy and its own context rules.
// The trade is deliberate: this package speaks the seven operations the Store
// contract needs, and nothing else.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/arandu-io/framework/observability"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/framework/storage"
)

// Config is a bucket on any S3-compatible service.
type Config struct {
	// Endpoint is the service, without the bucket:
	// https://<account>.r2.cloudflarestorage.com
	Endpoint string
	// Bucket is the bucket name.
	Bucket string
	// Region is what the signature is computed for. R2 wants "auto".
	Region string
	// AccessKey and SecretKey come from configuration, never from a literal.
	AccessKey string
	SecretKey string
	// Client is the HTTP client. Nil installs one with the instrumented
	// transport, so every call to the bucket shows up on the request timeline
	// rather than as unaccounted time.
	Client *http.Client
	// PathStyle puts the bucket in the path rather than in the host. R2 and
	// MinIO want it; Amazon deprecated it.
	PathStyle bool
}

// R2Config is the short form for Cloudflare R2.
type R2Config struct {
	// AccountID is the Cloudflare account, which is what the endpoint is
	// derived from.
	AccountID string
	Bucket    string
	AccessKey string
	SecretKey string
	Client    *http.Client
}

// R2 returns a store on Cloudflare R2.
//
// The endpoint and the region are derived rather than asked for, because
// getting either wrong produces a signature error that names neither.
func R2(cfg R2Config) (*Store, error) {
	if cfg.AccountID == "" {
		return nil, errors.New("storage/s3: R2 needs the account id, which is what the endpoint is built from")
	}
	return New(Config{
		Endpoint:  fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID),
		Bucket:    cfg.Bucket,
		Region:    "auto",
		AccessKey: cfg.AccessKey,
		SecretKey: cfg.SecretKey,
		Client:    cfg.Client,
		PathStyle: true,
	})
}

// Store is a bucket.
type Store struct {
	cfg    Config
	client *http.Client
}

// New returns a store on any S3-compatible service.
func New(cfg Config) (*Store, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("storage/s3: no endpoint")
	case cfg.Bucket == "":
		return nil, errors.New("storage/s3: no bucket")
	case cfg.AccessKey == "" || cfg.SecretKey == "":
		return nil, errors.New("storage/s3: no credentials")
	}
	if cfg.Region == "" {
		cfg.Region = "auto"
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")

	client := cfg.Client
	if client == nil {
		// The instrumented transport, so a slow bucket shows up on the timeline
		// as an outbound call rather than as "other".
		client = observability.Client(30 * time.Second)
	}
	return &Store{cfg: cfg, client: client}, nil
}

var _ storage.Store = (*Store)(nil)

// Put uploads a file under the tenant of the Grant.
func (s *Store) Put(ctx context.Context, g security.Grant, key string, body io.Reader, contentType string) error {
	full, err := storage.Path(g, key)
	if err != nil {
		return err
	}

	// Buffered because SigV4 signs the payload hash, and a hash needs the whole
	// body. Streaming uploads need the chunked signing variant, which is
	// another four hundred lines for a case this package does not have yet --
	// a file that does not fit in memory is a multipart upload, and that is the
	// trigger to write it.
	payload, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("storage/s3: reading the body of %s: %w", key, err)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	req, err := s.request(ctx, http.MethodPut, full, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if err := s.sign(req, payload); err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage/s3: uploading %s: %w", key, err)
	}
	defer drain(resp)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("storage/s3: uploading %s: %s", key, describe(resp))
	}
	return nil
}

// Get downloads a file.
func (s *Store) Get(ctx context.Context, g security.Grant, key string) (storage.File, error) {
	full, err := storage.Path(g, key)
	if err != nil {
		return storage.File{}, err
	}

	req, err := s.request(ctx, http.MethodGet, full, nil)
	if err != nil {
		return storage.File{}, err
	}
	if err := s.sign(req, nil); err != nil {
		return storage.File{}, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return storage.File{}, fmt.Errorf("storage/s3: downloading %s: %w", key, err)
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		// 403 is also not-found: a bucket policy that hides an object answers
		// forbidden, and telling the two apart would leak which keys exist.
		drain(resp)
		return storage.File{}, storage.ErrNotFound
	}
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("storage/s3: downloading %s: %s", key, describe(resp))
		drain(resp)
		return storage.File{}, err
	}

	modified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return storage.File{
		Key:         key,
		Size:        resp.ContentLength,
		ContentType: resp.Header.Get("Content-Type"),
		ModifiedAt:  modified,
		Body:        resp.Body,
	}, nil
}

// Delete removes a file. Removing what is not there is not an error.
func (s *Store) Delete(ctx context.Context, g security.Grant, key string) error {
	full, err := storage.Path(g, key)
	if err != nil {
		return err
	}

	req, err := s.request(ctx, http.MethodDelete, full, nil)
	if err != nil {
		return err
	}
	if err := s.sign(req, nil); err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage/s3: deleting %s: %w", key, err)
	}
	defer drain(resp)

	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("storage/s3: deleting %s: %s", key, describe(resp))
	}
	return nil
}

// Exists reports whether the key is there.
func (s *Store) Exists(ctx context.Context, g security.Grant, key string) (bool, error) {
	full, err := storage.Path(g, key)
	if err != nil {
		return false, err
	}

	req, err := s.request(ctx, http.MethodHead, full, nil)
	if err != nil {
		return false, err
	}
	if err := s.sign(req, nil); err != nil {
		return false, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("storage/s3: checking %s: %w", key, err)
	}
	defer drain(resp)

	switch {
	case resp.StatusCode == http.StatusOK:
		return true, nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("storage/s3: checking %s: %s", key, describe(resp))
	}
}

// listResult is what the bucket answers to a list, in the v2 shape.
type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// List returns the keys under a prefix, without the tenant part.
func (s *Store) List(ctx context.Context, g security.Grant, prefix string) ([]string, error) {
	base, err := storage.Path(g, ".keep")
	if err != nil {
		return nil, err
	}
	tenantPrefix := strings.TrimSuffix(base, ".keep")

	var out []string
	token := ""

	for {
		query := url.Values{}
		query.Set("list-type", "2")
		query.Set("prefix", tenantPrefix+prefix)
		if token != "" {
			query.Set("continuation-token", token)
		}

		req, err := s.request(ctx, http.MethodGet, "", nil)
		if err != nil {
			return nil, err
		}
		req.URL.RawQuery = query.Encode()
		if err := s.sign(req, nil); err != nil {
			return nil, err
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("storage/s3: listing %s: %w", prefix, err)
		}
		if resp.StatusCode >= 300 {
			err := fmt.Errorf("storage/s3: listing %s: %s", prefix, describe(resp))
			drain(resp)
			return nil, err
		}

		var result listResult
		decodeErr := xml.NewDecoder(resp.Body).Decode(&result)
		drain(resp)
		if decodeErr != nil {
			return nil, fmt.Errorf("storage/s3: reading the listing: %w", decodeErr)
		}

		for _, item := range result.Contents {
			// The tenant is stripped on the way out for the same reason it is
			// added on the way in: a caller that saw it could start passing it.
			out = append(out, strings.TrimPrefix(item.Key, tenantPrefix))
		}

		// A bucket with more than a thousand objects answers in pages, and
		// stopping at the first one silently loses the rest.
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return out, nil
		}
		token = result.NextContinuationToken
	}
}

// request builds the URL for a key.
func (s *Store) request(ctx context.Context, method, key string, body []byte) (*http.Request, error) {
	endpoint := s.cfg.Endpoint
	path := "/"

	if s.cfg.PathStyle {
		path = "/" + s.cfg.Bucket + "/"
	} else {
		host := strings.TrimPrefix(endpoint, "https://")
		endpoint = "https://" + s.cfg.Bucket + "." + host
	}
	if key != "" {
		path += escapePath(key)
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
	if err != nil {
		return nil, fmt.Errorf("storage/s3: building the request: %w", err)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	return req, nil
}

// escapePath encodes each segment, keeping the separators.
//
// url.PathEscape on the whole thing would encode the slashes and turn a nested
// key into one long name.
func escapePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func drain(resp *http.Response) {
	// Read what is left before closing, or the connection cannot be reused and
	// every call opens a new one.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// describe turns an error response into something readable.
//
// S3 answers XML with a Code and a Message, and a bare "403 Forbidden" sends
// people to check credentials when the actual problem is a bucket name.
func describe(resp *http.Response) string {
	var body struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err := xml.Unmarshal(raw, &body); err == nil && body.Code != "" {
		return fmt.Sprintf("%s (%s: %s)", resp.Status, body.Code, body.Message)
	}
	return resp.Status
}

// --- SigV4 ---

// sign adds the AWS Signature Version 4 headers.
//
// Two hundred lines against an SDK that brings a hundred modules, its own
// credential chain and its own retry policy. The algorithm has not changed
// since 2012 and is fully specified; the SDK's surface changes every quarter.
func (s *Store) sign(req *http.Request, payload []byte) error {
	now := time.Now().UTC()
	stamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	sum := sha256.Sum256(payload)
	hashed := hex.EncodeToString(sum[:])

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", hashed)

	signed, canonicalHeaders := canonicalize(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signed,
		hashed,
	}, "\n")

	scope := strings.Join([]string{date, s.cfg.Region, "s3", "aws4_request"}, "/")
	requestSum := sha256.Sum256([]byte(canonicalRequest))
	toSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		stamp,
		scope,
		hex.EncodeToString(requestSum[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+s.cfg.SecretKey), date)
	key = hmacSHA256(key, s.cfg.Region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.cfg.AccessKey, scope, signed, signature))
	return nil
}

// canonicalize returns the signed header list and the canonical header block.
func canonicalize(req *http.Request) (signed, canonical string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}

	for name, v := range req.Header {
		lower := strings.ToLower(name)
		names = append(names, lower)
		values[lower] = strings.TrimSpace(strings.Join(v, ","))
	}
	if _, has := values["host"]; !has {
		names = append(names, "host")
		values["host"] = req.URL.Host
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteString(":")
		b.WriteString(values[name])
		b.WriteString("\n")
	}
	return strings.Join(names, ";"), b.String()
}

// canonicalQuery sorts and encodes the query the way the signature expects.
func canonicalQuery(values url.Values) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range values[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
