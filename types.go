// Package licensex 提供 LicenseX v1 申请生成、验签和授权管理。
package licensex

import (
	"crypto/ed25519"
	"time"
)

// Payload 是经过签名的授权载荷。Limits 和 Features 字段必须存在。
// 空 map 或 slice 表示未授予任何明确额度或功能；未列出的额度应视为不可用，不能视为无限制。
type Payload struct {
	SchemaVersion int            `json:"schemaVersion"`         // 授权载荷的格式版本，必须等于 SchemaVersion，用于检查数据格式兼容性。
	LicenseID     string         `json:"licenseId"`             // 授权文件的唯一编号。
	KeyID         string         `json:"keyId"`                 // 签发时使用的密钥编号，用于选择受信公钥。
	Product       string         `json:"product"`               // 被授权的产品标识。
	CustomerID    string         `json:"customerId"`            // 客户的唯一标识。
	ProjectID     string         `json:"projectId"`             // 授权所属项目编号，与客户标识分别管理。
	Machine       Machine        `json:"machine"`               // 授权绑定的设备信息。
	Type          string         `json:"type"`                  // 授权类型：试用、永久或限时。
	IssuedAt      time.Time      `json:"issuedAt"`              // 授权开始生效的时间，必须使用 UTC。
	PublishedAt   *time.Time     `json:"publishedAt,omitempty"` // 授权实际生成发布时间；旧文件可能未记录，必须使用 UTC。
	ExpiresAt     *time.Time     `json:"expiresAt"`             // 授权截止时间；永久授权必须为 null，限时和试用授权必须填写。
	Limits        map[string]int `json:"limits"`                // 授予的额度，例如 robots；字段必须存在，未列出的额度不可用。
	Features      []string       `json:"features"`              // 授予的功能名称；字段必须存在，空数组表示未授予可选功能。
}

// Request 是提交给签发方的未签名机器申请。
type Request struct {
	SchemaVersion  int     `json:"schemaVersion"`  // 申请文件的格式版本，必须等于 SchemaVersion，与 ProductVersion 无关。
	ProductID      string  `json:"productId"`      // 申请授权的产品标识。
	ProductVersion string  `json:"productVersion"` // 生成申请时的产品版本。
	Machine        Machine `json:"machine"`        // 申请授权的设备信息。
}

// Machine 描述授权或申请文件中的设备绑定信息。
type Machine struct {
	Algorithm   string `json:"algorithm"`   // 机器码算法标识，用于说明机器码的计算规则和版本。
	MachineCode string `json:"machineCode"` // 按指定算法生成的设备机器码。
}

// Envelope 封装经过 Base64 编码的原始 JSON 字节及其签名。
type Envelope struct {
	Payload   string `json:"payload"`   // Base64 编码的授权载荷原始 JSON 字节。
	Signature string `json:"signature"` // 对载荷原始字节生成的 Base64 Ed25519 签名。
}

// PublicKeys 将受信任的密钥编号映射到 Ed25519 公钥。
// 公钥由调用方从可信来源提供，不能从授权文件中读取。
type PublicKeys map[string]ed25519.PublicKey

// VerifyOptions 指定授权文件必须匹配的产品、设备和校验时间。
type VerifyOptions struct {
	ProductID   string    // 当前产品标识。
	MachineCode string    // 当前设备的机器码。
	CurrentTime time.Time // 校验时间；零值表示使用当前系统时间。
}

// Status 是供授权管理页面展示的可信授权信息和时间状态。
// 业务准入应调用 Verify，并结合 RCS 的回拨和检查陈旧检测。
type Status struct {
	Payload                    // 原始授权内容。
	State         LicenseState `json:"state"`         // 激活及时间状态，不代表 RCS 的完整业务准入状态。
	RemainingDays int64        `json:"remainingDays"` // 剩余天数，不足一天向上取整；过期为 0，永久为 -1。
}

// ManagerOptions 固定当前产品、设备身份、受信公钥和存储。
// 配置必须来自可信来源，不能使用待验签授权中的值。
type ManagerOptions struct {
	ProductID  string // 当前产品的唯一标识
	PubKeys    PublicKeys
	Storage    Storage
	DeviceUUID string           // 留空时采集本机 UUID；显式指定时必须为部署设备的 UUID。
	Now        func() time.Time // 留空时使用 time.Now；自定义时间源必须可信且并发安全。
}
