package licensex

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParsePublicKey 解析 LicenseX 产品管理中复制的原始 Ed25519 公钥 Base64。
// 去除两端空白后按标准 Base64 解码，结果必须为 32 字节；不接受 PEM 或 X.509 公钥。
// 解析失败时返回包装了 ErrInvalidOptions 的错误，不返回部分公钥。
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("%w: public key Base64: %w", ErrInvalidOptions, err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be %d bytes", ErrInvalidOptions, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(key), nil
}

// ParsePublicKeys 将“密钥编号 → 原始公钥 Base64”配置转换为可用于验签的 PublicKeys。
// 配置至少包含一项，编号不得为空白且按原值保留；每把公钥使用 ParsePublicKey 解析。
// 任一项无效时返回包装了 ErrInvalidOptions 的错误，不返回部分配置。
func ParsePublicKeys(values map[string]string) (PublicKeys, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: at least one public key is required", ErrInvalidOptions)
	}
	keys := make(PublicKeys, len(values))
	for id, value := range values {
		if isBlank(id) {
			return nil, fmt.Errorf("%w: key ID must not be blank", ErrInvalidOptions)
		}
		key, err := ParsePublicKey(value)
		if err != nil {
			return nil, fmt.Errorf("licensex: public key %q: %w", id, err)
		}
		keys[id] = key
	}
	return keys, nil
}
