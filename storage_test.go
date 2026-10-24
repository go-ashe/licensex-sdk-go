package licensex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestFileStorageRoundTrip 验证原始字节保存、替换、文件权限及缺失文件错误。
func TestFileStorageRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "license.lic")
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := storage.Load(); !errors.Is(err, os.ErrNotExist) || data != nil {
		t.Fatalf("missing file = %q, %v", data, err)
	}
	for _, want := range [][]byte{[]byte("original license\n"), []byte("replacement\n")} {
		if err := storage.Save(want); err != nil {
			t.Fatal(err)
		}
		if got, err := storage.Load(); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Load = %q, %v; want %q", got, err, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("license is accessible to other users: %v", info.Mode())
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected files after save: %v, %v", entries, err)
	}
}

// TestFileStorageSizeLimits 验证空文件和超大文件被拒绝，保存失败保留旧数据。
func TestFileStorageSizeLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "license.lic")
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{'x'}, MaxLicenseSize)
	if err := storage.Save(want); err != nil {
		t.Fatal(err)
	}
	if got, err := storage.Load(); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("maximum-size file = %d bytes, %v", len(got), err)
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxLicenseSize+1)} {
		if err := storage.Save(data); !errors.Is(err, ErrMalformed) {
			t.Fatalf("invalid save error = %v", err)
		}
		if got, err := storage.Load(); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("failed save replaced old data: %d bytes, %v", len(got), err)
		}
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxLicenseSize+1)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := storage.Load(); !errors.Is(err, ErrMalformed) || got != nil {
			t.Fatalf("invalid stored file = %d bytes, %v", len(got), err)
		}
	}
}

// TestFileStorageInvalidConfiguration 验证非法配置和不存在的目录不会被静默接受。
func TestFileStorageInvalidConfiguration(t *testing.T) {
	for _, path := range []string{"", " \n"} {
		if storage, err := NewFileStorage(path); !errors.Is(err, ErrInvalidOptions) || storage != nil {
			t.Fatalf("invalid path returned %+v, %v", storage, err)
		}
	}
	for _, storage := range []*FileStorage{nil, {}} {
		if data, err := storage.Load(); !errors.Is(err, ErrInvalidOptions) || data != nil {
			t.Fatalf("uninitialized Load = %q, %v", data, err)
		}
		if err := storage.Save([]byte("license")); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("uninitialized Save = %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "missing", "license.lic")
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Save([]byte("license")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent error = %v", err)
	}
}

// TestFileStorageReplaceFailure 验证重命名失败时保留目标并清理临时文件。
func TestFileStorageReplaceFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "license.lic")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	storage, err := NewFileStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Save([]byte("license")); err == nil {
		t.Fatal("replacing a directory with a file succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "license.lic" || !entries[0].IsDir() {
		t.Fatalf("target changed or temporary file leaked: %v, %v", entries, err)
	}
}
