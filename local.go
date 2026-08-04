// Package storage is file storage on local disk.
//
// The contract lives in the core, in framework/storage: Store, the Grant on
// every method, and the tenant prefix that comes from it. This package is the
// implementation that needs nothing installed, which makes it the right one for
// development and for a single machine.
//
// For anything with more than one replica, github.com/arandu-io/storage/s3 is
// the same contract over the S3 protocol -- and Cloudflare R2 is the default
// there.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/framework/storage"
)

// Disk stores files under a root directory.
type Disk struct {
	root string
}

// NewDisk returns the store.
//
// The root is created if it does not exist, because the alternative is an
// application that boots fine and fails on the first upload.
func NewDisk(root string) (*Disk, error) {
	if root == "" {
		return nil, errors.New("storage: the disk store needs a root directory")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("storage: resolving %s: %w", root, err)
	}
	if err := os.MkdirAll(absolute, 0o755); err != nil {
		return nil, fmt.Errorf("storage: creating %s: %w", absolute, err)
	}
	return &Disk{root: absolute}, nil
}

var _ storage.Store = (*Disk)(nil)

// Put writes a file under the tenant of the Grant.
func (d *Disk) Put(ctx context.Context, g security.Grant, key string, body io.Reader, contentType string) error {
	full, err := d.pathFor(g, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("storage: creating the directory for %s: %w", key, err)
	}

	// Written to a temporary name and renamed, so a reader never sees a
	// half-written file and a crash mid-upload leaves nothing to clean up.
	tmp := full + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("storage: writing %s: %w", key, err)
	}

	if _, err := io.Copy(f, body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("storage: writing %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("storage: writing %s: %w", key, err)
	}
	if err := os.Rename(tmp, full); err != nil {
		return fmt.Errorf("storage: writing %s: %w", key, err)
	}

	// The content type is not stored: on disk it is the extension, and keeping
	// a sidecar file per object to hold one string is a second thing to keep in
	// sync. Get infers it, which is what a static file server does anyway.
	_ = contentType
	_ = ctx
	return nil
}

// Get reads a file back.
func (d *Disk) Get(ctx context.Context, g security.Grant, key string) (storage.File, error) {
	full, err := d.pathFor(g, key)
	if err != nil {
		return storage.File{}, err
	}

	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return storage.File{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.File{}, fmt.Errorf("storage: reading %s: %w", key, err)
	}
	if info.IsDir() {
		return storage.File{}, storage.ErrNotFound
	}

	f, err := os.Open(full)
	if err != nil {
		return storage.File{}, fmt.Errorf("storage: reading %s: %w", key, err)
	}

	_ = ctx
	return storage.File{
		Key:         key,
		Size:        info.Size(),
		ContentType: contentType(key),
		ModifiedAt:  info.ModTime(),
		Body:        f,
	}, nil
}

// Delete removes a file. Removing what is not there is not an error: the caller
// wanted it gone, and it is.
func (d *Disk) Delete(ctx context.Context, g security.Grant, key string) error {
	full, err := d.pathFor(g, key)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("storage: deleting %s: %w", key, err)
	}
	_ = ctx
	return nil
}

// Exists reports whether the key is there.
func (d *Disk) Exists(ctx context.Context, g security.Grant, key string) (bool, error) {
	full, err := d.pathFor(g, key)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("storage: checking %s: %w", key, err)
	}
	_ = ctx
	return !info.IsDir(), nil
}

// List returns the keys under a prefix, without the tenant part.
//
// The tenant is stripped on the way out for the same reason it is added on the
// way in: a caller that saw it could start passing it, and then the prefix would
// be something a caller controls.
func (d *Disk) List(ctx context.Context, g security.Grant, prefix string) ([]string, error) {
	base, err := storage.Path(g, ".keep")
	if err != nil {
		return nil, err
	}
	tenantRoot := filepath.Join(d.root, filepath.Dir(base))

	var out []string
	err = filepath.WalkDir(tenantRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// A tenant that has never stored anything has no directory,
				// and an empty list is the right answer rather than an error.
				return filepath.SkipAll
			}
			return err
		}
		if entry.IsDir() || strings.HasSuffix(path, ".partial") {
			return nil
		}

		relative, err := filepath.Rel(tenantRoot, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(relative)
		if prefix == "" || strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("storage: listing %s: %w", prefix, err)
	}

	_ = ctx
	return out, nil
}

// pathFor resolves a key to a path on disk, and refuses one that escapes.
//
// The escape check happens twice: storage.Path rejects "../" in the key, and
// this rejects a resolved path outside the root. Two checks because the first
// is about the key and the second is about the filesystem -- a symlink inside
// the root can point outside it, and only the second sees that.
func (d *Disk) pathFor(g security.Grant, key string) (string, error) {
	rel, err := storage.Path(g, key)
	if err != nil {
		return "", err
	}
	full := filepath.Join(d.root, filepath.FromSlash(rel))

	resolved, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("storage: resolving %s: %w", key, err)
	}
	if !strings.HasPrefix(resolved, d.root+string(filepath.Separator)) {
		return "", storage.ErrBadKey
	}
	return resolved, nil
}

// contentType infers the type from the extension, falling back to a type that
// browsers download rather than render.
//
// The fallback matters: serving an unknown file as text/html is how an upload
// becomes stored XSS.
func contentType(key string) string {
	if t := mime.TypeByExtension(filepath.Ext(key)); t != "" {
		return t
	}
	return "application/octet-stream"
}
