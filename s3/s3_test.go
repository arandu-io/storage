package s3_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arandu-io/framework/security"
	fw "github.com/arandu-io/framework/storage"
	"github.com/arandu-io/storage/s3"
)

// The tests drive a server that answers like a bucket. What is being checked is
// the protocol: the path a key lands on, the signature the request carries, the
// pagination of a listing, and the errors that have to be indistinguishable.
//
// Against a real bucket they would need credentials in CI, and the value would
// be proving that Cloudflare implements S3 -- which is not this package's claim.

const (
	tenantA = "11111111-1111-4111-8111-111111111111"
	tenantB = "22222222-2222-4222-8222-222222222222"
)

func grant(tenant string) security.Grant { return security.SystemGrant("file.write", tenant) }

// bucket returns a store pointed at a handler, plus what the handler saw.
func bucket(t *testing.T, handler http.HandlerFunc) (*s3.Store, *[]*http.Request) {
	t.Helper()

	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(context.Background()))
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	store, err := s3.New(s3.Config{
		Endpoint:  srv.URL,
		Bucket:    "uploads",
		Region:    "auto",
		AccessKey: "key",
		SecretKey: "secret",
		PathStyle: true,
		Client:    srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, &seen
}

// TestTheKeyLandsUnderTheTenant is the property the whole contract is built on,
// checked where it would actually break: in the URL.
func TestTheKeyLandsUnderTheTenant(t *testing.T) {
	store, seen := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	err := store.Put(context.Background(), grant(tenantA), "invoices/2026-08.pdf",
		strings.NewReader("the invoice"), "application/pdf")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("%d requests", len(*seen))
	}
	path := (*seen)[0].URL.Path
	if want := "/uploads/" + tenantA + "/invoices/2026-08.pdf"; path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
}

// TestTheRequestIsSigned: without the signature every call is a 403, and a
// signature that is present but wrong is the same 403 -- which is why the shape
// is worth checking here rather than discovering against a bucket.
func TestTheRequestIsSigned(t *testing.T) {
	store, seen := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if err := store.Put(context.Background(), grant(tenantA), "a.pdf", strings.NewReader("x"), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	req := (*seen)[0]
	auth := req.Header.Get("Authorization")
	for _, want := range []string{"AWS4-HMAC-SHA256", "Credential=key/", "SignedHeaders=", "Signature="} {
		if !strings.Contains(auth, want) {
			t.Errorf("the Authorization header has no %q: %s", want, auth)
		}
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("no X-Amz-Date, and the signature is scoped to it")
	}
	// The payload hash is signed, which is what makes a modified body fail.
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Error("no X-Amz-Content-Sha256")
	}
	if !strings.Contains(auth, "/auto/s3/aws4_request") {
		t.Errorf("the scope is not the configured region: %s", auth)
	}
}

func TestGetReturnsTheBody(t *testing.T) {
	store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("the invoice"))
	})

	f, err := store.Get(context.Background(), grant(tenantA), "a.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = f.Body.Close() }()

	body, _ := io.ReadAll(f.Body)
	if string(body) != "the invoice" {
		t.Fatalf("read %q", body)
	}
	if f.ContentType != "application/pdf" {
		t.Errorf("content type = %q", f.ContentType)
	}
}

// TestForbiddenAndMissingAreTheSameError: a bucket policy that hides an object
// answers 403, and telling the two apart would leak which keys exist.
func TestForbiddenAndMissingAreTheSameError(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})

		if _, err := store.Get(context.Background(), grant(tenantA), "a.pdf"); !errors.Is(err, fw.ErrNotFound) {
			t.Errorf("status %d gave %v, want ErrNotFound", status, err)
		}
		exists, err := store.Exists(context.Background(), grant(tenantA), "a.pdf")
		if err != nil || exists {
			t.Errorf("status %d: exists = %v (%v)", status, exists, err)
		}
	}
}

// TestAnErrorSaysWhatTheBucketSaid: a bare "403 Forbidden" sends people to check
// credentials when the actual problem is the bucket name.
func TestAnErrorSaysWhatTheBucketSaid(t *testing.T) {
	store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
	})

	err := store.Put(context.Background(), grant(tenantA), "a.pdf", strings.NewReader("x"), "")
	if err == nil {
		t.Fatal("a 400 was accepted")
	}
	if !strings.Contains(err.Error(), "NoSuchBucket") {
		t.Errorf("the error does not carry what the bucket said: %v", err)
	}
}

// TestListPaginates: a bucket with more than a thousand objects answers in
// pages, and stopping at the first silently loses the rest.
func TestListPaginates(t *testing.T) {
	page := 0
	store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`<ListBucketResult>
				<Contents><Key>` + tenantA + `/a.pdf</Key></Contents>
				<IsTruncated>true</IsTruncated>
				<NextContinuationToken>more</NextContinuationToken>
			</ListBucketResult>`))
			return
		}
		_, _ = w.Write([]byte(`<ListBucketResult>
			<Contents><Key>` + tenantA + `/b.pdf</Key></Contents>
			<IsTruncated>false</IsTruncated>
		</ListBucketResult>`))
	})

	keys, err := store.List(context.Background(), grant(tenantA), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("listed %v, want both pages", keys)
	}
	// The tenant is stripped on the way out, or a caller could start passing it.
	for _, key := range keys {
		if strings.Contains(key, tenantA) {
			t.Errorf("the key leaks the tenant: %q", key)
		}
	}
}

// TestTheListingIsScopedToTheTenant: without the prefix, one tenant lists
// every file in the bucket.
func TestTheListingIsScopedToTheTenant(t *testing.T) {
	store, seen := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`))
	})

	if _, err := store.List(context.Background(), grant(tenantB), "invoices/"); err != nil {
		t.Fatalf("List: %v", err)
	}

	prefix := (*seen)[0].URL.Query().Get("prefix")
	if !strings.HasPrefix(prefix, tenantB+"/") {
		t.Fatalf("prefix = %q, want it scoped to the tenant", prefix)
	}
	if !strings.HasSuffix(prefix, "invoices/") {
		t.Errorf("prefix = %q, want the caller's prefix inside it", prefix)
	}
}

func TestAGrantWithoutATenantIsRefused(t *testing.T) {
	store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {})

	err := store.Put(context.Background(), grant(""), "a.pdf", strings.NewReader("x"), "")
	if !errors.Is(err, fw.ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
}

func TestAKeyCannotEscapeTheTenant(t *testing.T) {
	store, _ := bucket(t, func(w http.ResponseWriter, _ *http.Request) {})

	err := store.Put(context.Background(), grant(tenantA), "../"+tenantB+"/secret.pdf",
		strings.NewReader("x"), "")
	if !errors.Is(err, fw.ErrBadKey) {
		t.Fatalf("err = %v, want ErrBadKey", err)
	}
}

// TestR2DerivesItsEndpoint: getting the endpoint or the region wrong produces a
// signature error that names neither, so neither is asked for.
func TestR2DerivesItsEndpoint(t *testing.T) {
	if _, err := s3.R2(s3.R2Config{Bucket: "uploads", AccessKey: "k", SecretKey: "s"}); err == nil {
		t.Error("R2 without an account id was accepted")
	}

	store, err := s3.R2(s3.R2Config{
		AccountID: "abc123", Bucket: "uploads", AccessKey: "k", SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("R2: %v", err)
	}
	if store == nil {
		t.Fatal("R2 returned nothing")
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  s3.Config
	}{
		{"no endpoint", s3.Config{Bucket: "b", AccessKey: "k", SecretKey: "s"}},
		{"no bucket", s3.Config{Endpoint: "https://x", AccessKey: "k", SecretKey: "s"}},
		{"no credentials", s3.Config{Endpoint: "https://x", Bucket: "b"}},
	} {
		if _, err := s3.New(c.cfg); err == nil {
			t.Errorf("%s was accepted", c.name)
		}
	}
}

// TestAKeyWithSpacesIsEscapedPerSegment: escaping the whole path would encode
// the slashes and turn a nested key into one long name.
func TestAKeyWithSpacesIsEscapedPerSegment(t *testing.T) {
	store, seen := bucket(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	if err := store.Put(context.Background(), grant(tenantA), "my folder/my file.pdf",
		strings.NewReader("x"), ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw := (*seen)[0].URL.EscapedPath()
	if strings.Contains(raw, "%2F") {
		t.Errorf("the separators were escaped: %s", raw)
	}
	if !strings.Contains(raw, "%20") {
		t.Errorf("the spaces were not escaped: %s", raw)
	}
}
