package licensex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestParsePublicKey 验证原始公钥 Base64 可直接解析，并允许复制时附带的两端空白。
func TestParsePublicKey(t *testing.T) {
	want := testPrivateKey().Public().(ed25519.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(want)
	for _, value := range []string{encoded, " \n" + encoded + "\t "} {
		got, err := ParsePublicKey(value)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("parsed public key = %x, %v; want %x", got, err, want)
		}
	}
}

// TestParsePublicKeyRejectsInvalidInput 验证无效编码、错误长度和非原始公钥格式被拒绝。
func TestParsePublicKeyRejectsInvalidInput(t *testing.T) {
	pkix, err := x509.MarshalPKIXPublicKey(testPrivateKey().Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value string
	}{
		// 空输入及纯空白不能作为受信公钥。
		{"empty", ""},
		{"blank", " \n\t"},
		// 非法字符和非零填充位不能通过标准 Base64 严格解码。
		{"invalid Base64", "!"},
		{"invalid padding bits", strings.Repeat("A", 42) + "B="},
		// 解码结果必须恰好为 Ed25519 公钥的 32 字节。
		{"short key", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))},
		{"long key", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize+1))},
		// 私钥、X.509 容器和 PEM 文本不能替代产品管理提供的原始公钥。
		{"private key", base64.StdEncoding.EncodeToString(testPrivateKey())},
		{"X.509 key", base64.StdEncoding.EncodeToString(pkix)},
		{"PEM key", "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(pkix) + "\n-----END PUBLIC KEY-----"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParsePublicKey(tc.value)
			if key != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("invalid public key returned %x, %v", key, err)
			}
		})
	}
}

// TestParsePublicKeys 验证多组密钥编号与 Base64 公钥的对应关系，以及解析结果可直接用于验签。
func TestParsePublicKeys(t *testing.T) {
	current := testPrivateKey().Public().(ed25519.PublicKey)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	keys, err := ParsePublicKeys(map[string]string{
		"test-key": base64.StdEncoding.EncodeToString(current),
		"next-key": base64.StdEncoding.EncodeToString(next),
	})
	if err != nil || len(keys) != 2 || !bytes.Equal(keys["test-key"], current) || !bytes.Equal(keys["next-key"], next) {
		t.Fatalf("parsed keyring = %v, %v", keys, err)
	}
	// 使用复制的编号选择公钥，验证真实签名文件，而非只检查解码后的字节。
	want := testPayload(t)
	got, err := Verify(testSign(t, want), keys, testOptions(want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("verify with parsed keyring = %+v, %v; want %+v", got, err, want)
	}
}

// TestParsePublicKeysRejectsInvalidConfiguration 验证配置失败时返回明确错误且不暴露部分可用配置。
func TestParsePublicKeysRejectsInvalidConfiguration(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(testPrivateKey().Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name   string
		values map[string]string
	}{
		// 未配置任何公钥时无法建立信任关系。
		{"nil", nil},
		{"empty", map[string]string{}},
		// 密钥编号必须有实际内容。
		{"empty ID", map[string]string{"": valid}},
		{"blank ID", map[string]string{" \n": valid}},
		// 即使已有有效项，其余项无效时也必须拒绝整组配置。
		{"invalid key", map[string]string{"test-key": valid, "next-key": "!"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParsePublicKeys(tc.values)
			if keys != nil || !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("invalid keyring returned %v, %v", keys, err)
			}
		})
	}
}
