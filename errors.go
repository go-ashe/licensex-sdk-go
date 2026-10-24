package licensex

import "errors"

var (
	// ErrMalformed 表示授权文件或请求文件格式错误。
	ErrMalformed = errors.New("licensex: malformed data")
	// ErrUnsupported 表示授权格式版本或签名算法不受支持。
	ErrUnsupported = errors.New("licensex: unsupported schema or algorithm")
	// ErrUnknownKey 表示授权使用了调用方未信任的签名密钥。
	ErrUnknownKey = errors.New("licensex: unknown signing key")
	// ErrBadSignature 表示授权签名无效。
	ErrBadSignature = errors.New("licensex: invalid signature")
	// ErrInvalidPayload 表示授权载荷缺少必填字段或字段值不符合规则。
	ErrInvalidPayload = errors.New("licensex: invalid payload")
	// ErrWrongProduct 表示授权签发给了其他产品。
	ErrWrongProduct = errors.New("licensex: product mismatch")
	// ErrWrongMachine 表示授权绑定的机器与当前机器不匹配。
	ErrWrongMachine = errors.New("licensex: machine mismatch")
	// ErrNotYetValid 表示授权尚未到生效时间。
	ErrNotYetValid = errors.New("licensex: not yet valid")
	// ErrExpired 表示授权已过期。
	ErrExpired = errors.New("licensex: expired")
	// ErrInvalidRequest 表示授权请求缺少必填字段或字段值不符合规则。
	ErrInvalidRequest = errors.New("licensex: invalid request")
	// ErrInvalidVerifyOptions 表示验签时没有提供产品标识或机器码。
	ErrInvalidVerifyOptions = errors.New("licensex: product and machine code are required")
	// ErrNotActivated 表示管理器尚未加载或导入可信授权。
	ErrNotActivated = errors.New("licensex: no active license")
	// ErrInvalidOptions 表示管理器或存储配置无效。
	ErrInvalidOptions = errors.New("licensex: invalid options")
)
