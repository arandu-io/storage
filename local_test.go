package storage_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arandu-io/framework/security"
	fw "github.com/arandu-io/framework/storage"
	"github.com/arandu-io/storage"
)

const (
	tenantA = "11111111-1111-4111-8111-111111111111"
	tenantB = "22222222-2222-4222-8222-222222222222"
)

func grant(tenant string) security.Grant { return security.SystemGrant("file.write", tenant) }

func disk(t *testing.T) *storage.Disk {
	t.Helper()
	d, err := storage.NewDisk(filepath.Join(t.TempDir(), "files"))
	if err != nil {
		t.Fatalf("NewDisk: %v", err)
	}
	return d
}

func put(t *testing.T, d *storage.Disk, tenant, key, body string) {
	t.Helper()
	if err := d.Put(context.Background(), grant(tenant), key, strings.NewReader(body), ""); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
}

func TestRoundTrip(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	put(t, d, tenantA, "invoices/2026-08.pdf", "the invoice")

	f, err := d.Get(ctx, grant(tenantA), "invoices/2026-08.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = f.Body.Close() }()

	body, err := io.ReadAll(f.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "the invoice" {
		t.Fatalf("read %q", body)
	}
	if f.Size != int64(len("the invoice")) {
		t.Errorf("size = %d", f.Size)
	}
	if f.ContentType != "application/pdf" {
		t.Errorf("content type = %q", f.ContentType)
	}
}

// TestOneTenantCannotReadAnother is the reason every method takes a Grant. A
// file is customer data, and this is the test that says so.
func TestOneTenantCannotReadAnother(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	put(t, d, tenantA, "secret.pdf", "theirs")

	if _, err := d.Get(ctx, grant(tenantB), "secret.pdf"); !errors.Is(err, fw.ErrNotFound) {
		t.Fatalf("another tenant read the file: %v", err)
	}
	if exists, err := d.Exists(ctx, grant(tenantB), "secret.pdf"); err != nil || exists {
		t.Fatalf("another tenant sees the file: %v (%v)", exists, err)
	}
	// And its own delete does not touch the other's file.
	if err := d.Delete(ctx, grant(tenantB), "secret.pdf"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if exists, err := d.Exists(ctx, grant(tenantA), "secret.pdf"); err != nil || !exists {
		t.Fatal("one tenant's delete removed another tenant's file")
	}
}

// TestAKeyCannotEscapeTheRoot is the second of the two checks: the first is
// about the key, this one is about the filesystem.
func TestAKeyCannotEscapeTheRoot(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	for _, key := range []string{"../../etc/passwd", "../" + tenantB + "/secret.pdf", ".."} {
		if err := d.Put(ctx, grant(tenantA), key, strings.NewReader("x"), ""); err == nil {
			t.Errorf("%q was written", key)
		}
		if _, err := d.Get(ctx, grant(tenantA), key); err == nil {
			t.Errorf("%q was read", key)
		}
	}
}

func TestAGrantWithoutATenantIsRefused(t *testing.T) {
	d := disk(t)

	err := d.Put(context.Background(), grant(""), "x.pdf", strings.NewReader("x"), "")
	if !errors.Is(err, fw.ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}
}

// TestListStaysWithinTheTenant: the tenant is stripped on the way out for the
// same reason it is added on the way in -- a caller that saw it could start
// passing it.
func TestListStaysWithinTheTenant(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	put(t, d, tenantA, "invoices/a.pdf", "a")
	put(t, d, tenantA, "invoices/b.pdf", "b")
	put(t, d, tenantA, "avatars/c.png", "c")
	put(t, d, tenantB, "invoices/theirs.pdf", "theirs")

	all, err := d.List(ctx, grant(tenantA), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("listed %v, want three of its own", all)
	}
	for _, key := range all {
		if strings.Contains(key, tenantA) || strings.Contains(key, tenantB) {
			t.Errorf("the key leaks the tenant: %q", key)
		}
		if strings.Contains(key, "theirs") {
			t.Errorf("another tenant's file was listed: %q", key)
		}
	}

	invoices, err := d.List(ctx, grant(tenantA), "invoices/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(invoices) != 2 {
		t.Fatalf("the prefix returned %v", invoices)
	}
}

// TestListingATenantWithNothingIsEmpty: a tenant that never stored anything has
// no directory, and that is an empty list rather than an error.
func TestListingATenantWithNothingIsEmpty(t *testing.T) {
	d := disk(t)

	keys, err := d.List(context.Background(), grant(tenantA), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("listed %v", keys)
	}
}

// TestAPartialWriteIsNotVisible: written to a temporary name and renamed, so a
// reader never sees half a file and a crash mid-upload leaves nothing behind.
func TestAPartialWriteIsNotVisible(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	err := d.Put(ctx, grant(tenantA), "broken.pdf", failingReader{}, "")
	if err == nil {
		t.Fatal("a failing upload reported success")
	}

	if exists, _ := d.Exists(ctx, grant(tenantA), "broken.pdf"); exists {
		t.Fatal("a failed upload left the file in place")
	}
	// And no leftover to clean up.
	keys, _ := d.List(ctx, grant(tenantA), "")
	for _, key := range keys {
		if strings.HasSuffix(key, ".partial") {
			t.Errorf("a partial file was left behind: %s", key)
		}
	}
}

// TestAnUnknownTypeIsNotHTML: serving an unknown file as text/html is how an
// upload becomes stored XSS.
func TestAnUnknownTypeIsNotHTML(t *testing.T) {
	d := disk(t)
	ctx := context.Background()

	put(t, d, tenantA, "payload.weird", "<script>alert(1)</script>")

	f, err := d.Get(ctx, grant(tenantA), "payload.weird")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Body.Close() }()

	if strings.Contains(f.ContentType, "html") {
		t.Fatalf("content type = %q, and the browser would render it", f.ContentType)
	}
}

func TestDeletingWhatIsNotThereIsFine(t *testing.T) {
	d := disk(t)

	if err := d.Delete(context.Background(), grant(tenantA), "never-existed.pdf"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestTheRootIsCreated: the alternative is an application that boots fine and
// fails on the first upload.
func TestTheRootIsCreated(t *testing.T) {
	root := filepath.Join(t.TempDir(), "a", "b", "files")

	if _, err := storage.NewDisk(root); err != nil {
		t.Fatalf("NewDisk: %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("the root was not created: %v", err)
	}
}

// failingReader fails halfway, like a connection dropping mid-upload.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the connection dropped") }
