package licensex

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ParsePayload 解析授权 JSON，拒绝未知字段和缺少 expiresAt 的载荷。
// 本函数不验签，也不校验授权权益；签发前调用 ValidatePayload，客户侧调用 Verify。
func ParsePayload(data []byte) (Payload, error) {
	if len(data) == 0 || len(data) > MaxLicenseSize {
		return Payload{}, fmt.Errorf("%w: payload size", ErrMalformed)
	}
	var payload Payload
	// 单独接收 expiresAt，以区分“字段缺失”和“明确填写 null”。
	fields := struct {
		*Payload
		ExpiresAt json.RawMessage `json:"expiresAt"`
	}{Payload: &payload}
	if err := decodeJSON(data, &fields); err != nil {
		return Payload{}, fmt.Errorf("%w: payload JSON: %w", ErrMalformed, err)
	}
	if len(fields.ExpiresAt) == 0 {
		return Payload{}, fmt.Errorf("%w: expiresAt is required", ErrMalformed)
	}
	if err := json.Unmarshal(fields.ExpiresAt, &payload.ExpiresAt); err != nil {
		return Payload{}, fmt.Errorf("%w: expiresAt: %w", ErrMalformed, err)
	}
	return payload, nil
}

// parseFile 检查授权文件大小，解析外层 JSON 并解码 Base64 载荷和签名。
// 返回原始载荷字节及 Ed25519 签名，不解析载荷字段或验证签名真实性。
func parseFile(data []byte) ([]byte, []byte, error) {
	if len(data) == 0 || len(data) > MaxLicenseSize {
		return nil, nil, fmt.Errorf("%w: file size", ErrMalformed)
	}
	var envelope Envelope
	if err := decodeJSON(data, &envelope); err != nil {
		return nil, nil, fmt.Errorf("%w: envelope: %w", ErrMalformed, err)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 {
		return nil, nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	return payload, signature, nil
}

// decodeJSON 将单个 JSON 值解码到 destination，拒绝未知字段及尾随数据。
func decodeJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON 末尾存在多余或无效内容")
	}
	return nil
}

// now 返回指定的校验时间；CurrentTime 为零值时使用当前系统时间。
func (options VerifyOptions) now() time.Time {
	if options.CurrentTime.IsZero() {
		return time.Now()
	}
	return options.CurrentTime
}

// Verify 验证文件签名、授权字段、产品、设备和有效期。
// 只有全部检查通过时才返回授权内容。
func Verify(file []byte, trustedKeys PublicKeys, options VerifyOptions) (Payload, error) {
	payload, err := verifyPayload(file, trustedKeys, options)
	if err != nil {
		return Payload{}, err
	}
	switch stateAt(payload, options.now()) {
	case LicenseStateValid:
		return payload, nil
	case LicenseStateNotYetValid:
		return Payload{}, ErrNotYetValid
	default:
		return Payload{}, ErrExpired
	}
}

// verifyPayload 校验文件真实性及其适用的产品和设备，不判断有效期。
func verifyPayload(file []byte, trustedKeys PublicKeys, options VerifyOptions) (Payload, error) {
	if isBlank(options.ProductID) || isBlank(options.MachineCode) {
		return Payload{}, ErrInvalidVerifyOptions
	}
	payloadBytes, signature, err := parseFile(file)
	if err != nil {
		return Payload{}, err
	}
	payload, err := ParsePayload(payloadBytes)
	if err != nil {
		return Payload{}, err
	}
	// 验签前仅使用 keyId 查找可信公钥，不信任任何授权权益。
	publicKey, exists := trustedKeys[payload.KeyID]
	if !exists {
		return Payload{}, ErrUnknownKey
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payloadBytes, signature) {
		return Payload{}, ErrBadSignature
	}
	if err = ValidatePayload(payload); err != nil {
		return Payload{}, err
	}
	if payload.Product != options.ProductID {
		return Payload{}, ErrWrongProduct
	}
	if payload.Machine.MachineCode != options.MachineCode {
		return Payload{}, ErrWrongMachine
	}
	return payload, nil
}

// VerifyStatus 验证授权后返回页面数据；过期和未生效的授权仍可查看详情。
// 验签失败、字段无效、产品或设备不匹配时返回错误。
func VerifyStatus(file []byte, trustedKeys PublicKeys, options VerifyOptions) (Status, error) {
	payload, err := verifyPayload(file, trustedKeys, options)
	if err != nil {
		return Status{}, err
	}
	return statusFor(payload, options.now()), nil
}

// statusFor 根据已验证的授权和指定时间生成展示状态，永久授权的剩余天数为 -1。
// 本函数不复制载荷中的引用数据，需要隔离时由调用方复制。
func statusFor(payload Payload, now time.Time) Status {
	status := Status{Payload: payload, State: stateAt(payload, now), RemainingDays: -1}
	if payload.ExpiresAt != nil {
		status.RemainingDays = daysUntil(*payload.ExpiresAt, now)
	}
	return status
}

// stateAt 按指定时间判断授权是否生效：生效时刻包含在有效期内，截止时刻不包含。
// 调用前须确保载荷已通过校验；永久授权只检查生效时间。
func stateAt(payload Payload, now time.Time) LicenseState {
	if now.Before(payload.IssuedAt) {
		return LicenseStateNotYetValid
	}
	if payload.ExpiresAt != nil && !now.Before(*payload.ExpiresAt) {
		return LicenseStateExpired
	}
	return LicenseStateValid
}

// daysUntil 计算距离截止时间的剩余天数，不足一天向上取整，到期后返回 0。
// 使用秒和纳秒计算，支持超过 time.Duration 可表示范围的有效期。
func daysUntil(expiresAt, now time.Time) int64 {
	if !now.Before(expiresAt) {
		return 0
	}
	// 使用秒数和纳秒计算，避免浮点取整误差以及 time.Duration 的跨度限制。
	const secondsPerDay = 24 * 60 * 60
	seconds := expiresAt.Unix() - now.Unix()
	days := seconds / secondsPerDay
	if seconds%secondsPerDay != 0 || expiresAt.Nanosecond() > now.Nanosecond() {
		days++
	}
	return days
}

// ValidatePayload 校验授权字段，不依赖当前时间、产品安装信息或当前设备。
func ValidatePayload(payload Payload) error {
	if payload.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schemaVersion", ErrUnsupported)
	}
	for _, field := range []struct{ name, value string }{
		{"licenseId", payload.LicenseID},
		{"keyId", payload.KeyID},
		{"product", payload.Product},
		{"customerId", payload.CustomerID},
		{"projectId", payload.ProjectID},
	} {
		if isBlank(field.value) {
			return fmt.Errorf("%w: %s is required", ErrInvalidPayload, field.name)
		}
	}
	if !isValidBinding(payload.Machine) {
		return fmt.Errorf("%w: machine", ErrInvalidPayload)
	}
	if !isUTC(payload.IssuedAt) {
		return fmt.Errorf("%w: issuedAt must be a non-zero UTC time", ErrInvalidPayload)
	}
	if payload.PublishedAt != nil && !isUTC(*payload.PublishedAt) {
		return fmt.Errorf("%w: publishedAt must be a non-zero UTC time", ErrInvalidPayload)
	}
	switch payload.Type {
	case TypePerpetual:
		if payload.ExpiresAt != nil {
			return fmt.Errorf("%w: perpetual license has expiresAt", ErrInvalidPayload)
		}
	case TypeTrial, TypeTimeLimited:
		if payload.ExpiresAt == nil || !isUTC(*payload.ExpiresAt) || !payload.ExpiresAt.After(payload.IssuedAt) {
			return fmt.Errorf("%w: invalid expiresAt", ErrInvalidPayload)
		}
	default:
		return fmt.Errorf("%w: license type", ErrInvalidPayload)
	}
	if payload.Limits == nil || payload.Features == nil {
		return fmt.Errorf("%w: limits and features must be present", ErrInvalidPayload)
	}
	for name, value := range payload.Limits {
		if isBlank(name) || value <= 0 {
			return fmt.Errorf("%w: limit %q must have a name and positive value", ErrInvalidPayload, name)
		}
	}
	features := make(map[string]bool, len(payload.Features))
	for _, feature := range payload.Features {
		if isBlank(feature) || features[feature] {
			return fmt.Errorf("%w: empty or duplicate feature %q", ErrInvalidPayload, feature)
		}
		features[feature] = true
	}
	return nil
}

// isBlank 判断字符串是否为空或仅包含空白字符。
func isBlank(value string) bool { return strings.TrimSpace(value) == "" }

// isUTC 判断时间是否非零且时区偏移量为零。
func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0
}

// isValidBinding 检查机器码算法、版本前缀、长度和十六进制格式，不验证设备归属。
func isValidBinding(binding Machine) bool {
	code := binding.MachineCode
	if binding.Algorithm != MachineAlgorithmDMIUUIDSHA256V1 ||
		!strings.HasPrefix(code, "v1:") || len(code) != 3+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(code[3:])
	return err == nil
}
