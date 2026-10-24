package licensex

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Storage 保存未经重新编码的原始签名文件。
// Save 必须原子替换：返回错误时保留原文件；实现不得修改传入的字节。
// Load 在尚无文件时应返回可用 errors.Is(err, os.ErrNotExist) 识别的错误。
type Storage interface {
	// Load 返回原始签名文件；尚无授权时返回可用 errors.Is 识别的 os.ErrNotExist。
	Load() ([]byte, error)
	// Save 原子替换原始签名文件；失败时保留旧文件，且不得修改传入的数据。
	Save(data []byte) error
}

// FileStorage 在固定路径保存授权。通过 NewFileStorage 创建，可供并发调用。
// 父目录应预先创建；多次成功保存时，最后一次原子替换的文件生效。
type FileStorage struct {
	path string
}

// NewFileStorage 校验非空路径并将其转换为绝对路径，不创建文件或父目录。
func NewFileStorage(path string) (*FileStorage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: empty license path", ErrInvalidOptions)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("%w: license path: %w", ErrInvalidOptions, err)
	}
	return &FileStorage{path: absolute}, nil
}

// Load 限长读取授权，避免在验签前加载任意大的文件。
func (s *FileStorage) Load() ([]byte, error) {
	if s == nil || s.path == "" {
		return nil, fmt.Errorf("%w: uninitialized file storage", ErrInvalidOptions)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("licensex: open license: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxLicenseSize+1))
	if err != nil {
		return nil, fmt.Errorf("licensex: read license: %w", err)
	}
	if len(data) == 0 || len(data) > MaxLicenseSize {
		return nil, fmt.Errorf("%w: stored license size", ErrMalformed)
	}
	return data, nil
}

// Save 在同目录创建 0600 临时文件，写入并同步后原子替换目标。
// 只负责存储；调用方须先验签。成功返回后不保证断电时目录项的持久性。
func (s *FileStorage) Save(data []byte) error {
	if s == nil || s.path == "" {
		return fmt.Errorf("%w: uninitialized file storage", ErrInvalidOptions)
	}
	if len(data) == 0 || len(data) > MaxLicenseSize {
		return fmt.Errorf("%w: license file size", ErrMalformed)
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".licensex-*")
	if err != nil {
		return fmt.Errorf("licensex: create temporary license: %w", err)
	}
	defer os.Remove(file.Name())
	// 失败路径也必须关闭文件。重命名前显式检查 Close 的结果。
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("licensex: write temporary license: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("licensex: sync temporary license: %w", err)
	}
	err = file.Close()
	closed = true
	if err != nil {
		return fmt.Errorf("licensex: close temporary license: %w", err)
	}
	if err := os.Rename(file.Name(), s.path); err != nil {
		return fmt.Errorf("licensex: replace license: %w", err)
	}
	return nil
}
