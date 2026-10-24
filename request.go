package licensex

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// GenerateRequest 使用显式设备 UUID 生成 LicenseX v1 申请。
// 产品标识和版本去除两端空白；UUID 的规范化规则与 GenerateMachineCode 相同。
func GenerateRequest(productID, productVersion, deviceUUID string) (Request, error) {
	productID, productVersion = strings.TrimSpace(productID), strings.TrimSpace(productVersion)
	if err := validateRequestProduct(productID, productVersion); err != nil {
		return Request{}, err
	}

	code, err := GenerateMachineCode(productID, deviceUUID)
	if err != nil {
		return Request{}, err
	}

	return Request{
		SchemaVersion:  SchemaVersion,
		ProductID:      productID,
		ProductVersion: productVersion,
		Machine: Machine{
			Algorithm:   MachineAlgorithmDMIUUIDSHA256V1,
			MachineCode: code,
		},
	}, nil
}

// ValidateRequest 检查申请字段和机器码格式，不验证设备归属或商业权益。
func ValidateRequest(request Request) error {
	if request.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schemaVersion", ErrInvalidRequest)
	}

	if err := validateRequestProduct(request.ProductID, request.ProductVersion); err != nil {
		return err
	}

	if !isValidBinding(request.Machine) {
		return fmt.Errorf("%w: machine", ErrInvalidRequest)
	}
	return nil
}

// validateRequestProduct 检查申请的产品标识和版本是否为非空 UTF-8 文本且未超长。
func validateRequestProduct(productID, productVersion string) error {
	for _, field := range []struct{ name, value string }{
		{"productId", productID}, {"productVersion", productVersion},
	} {
		if err := validateRequestText(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

// validateRequestText 检查文本非空、UTF-8 编码和字节数上限，不修改原值。
// name 用于错误信息；校验失败时返回包装了 ErrInvalidRequest 的错误。
func validateRequestText(name, value string) error {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be non-empty UTF-8 text", ErrInvalidRequest, name)
	}
	if len(value) > MaxRequestSize {
		return fmt.Errorf("%w: %s exceeds size limit", ErrInvalidRequest, name)
	}
	return nil
}

// MarshalRequest 校验并编码申请，输出带缩进和末尾换行的 JSON。
// 返回值可作为 HTTP 下载内容；不超过 MaxRequestSize 字节。
func MarshalRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("licensex: encode request: %w", err)
	}

	data = append(data, '\n')
	if len(data) > MaxRequestSize {
		return nil, fmt.Errorf("%w: encoded request exceeds %d bytes", ErrInvalidRequest, MaxRequestSize)
	}
	return data, nil
}

// WriteRequest 导出申请 JSON。父目录必须存在，已有文件不会被覆盖。
// 文件以 0644 权限创建（受 umask 约束）；写入失败时清理本次创建的文件。
func WriteRequest(path string, request Request) (err error) {
	data, err := MarshalRequest(request)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("licensex: create request file: %w", err)
	}

	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("licensex: close request file: %w", closeErr)
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()

	if _, err = file.Write(data); err != nil {
		return fmt.Errorf("licensex: write request file: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("licensex: sync request file: %w", err)
	}
	return nil
}
