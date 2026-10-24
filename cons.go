package licensex

const (
	// SchemaVersion 是申请和授权 JSON 的数据结构版本。
	// SDK 据此检查文件格式是否受支持，与产品版本和授权有效期无关。
	SchemaVersion = 1

	// MachineAlgorithmDMIUUIDSHA256V1 标识当前支持的机器码算法。
	// 使用产品标识和规范化设备 UUID 计算 SHA-256，机器码以 "v1:" 开头。
	MachineAlgorithmDMIUUIDSHA256V1 = "dmi-uuid-sha256-v1"

	// MaxLicenseSize 是授权文件及解码后载荷各自的大小上限，单位为字节：1 MiB。
	MaxLicenseSize = 1 << 20

	// MaxRequestSize 是申请 JSON 编码后的大小上限，单位为字节：1 MiB。
	// 产品标识和产品版本也分别受此字节数上限约束。
	MaxRequestSize = 1 << 20
)

const (
	// TypeTrial 表示试用授权，ExpiresAt 必须晚于 IssuedAt。
	TypeTrial = "trial"
	// TypePerpetual 表示永久授权，ExpiresAt 必须为 nil，仍受 IssuedAt 约束。
	TypePerpetual = "perpetual"
	// TypeTimeLimited 表示限时授权，ExpiresAt 必须晚于 IssuedAt。
	TypeTimeLimited = "time_limited"
)

// LicenseState 表示授权的激活及时间状态。
type LicenseState string

const (
	// LicenseStateNotActivated 表示尚未加载或导入可信授权。
	LicenseStateNotActivated LicenseState = "not_activated"
	// LicenseStateValid 表示授权已生效且未过期；当前时间达到 IssuedAt 时即生效。
	LicenseStateValid LicenseState = "valid"
	// LicenseStateNotYetValid 表示授权尚未生效，当前时间早于 IssuedAt。
	LicenseStateNotYetValid LicenseState = "not_yet_valid"
	// LicenseStateExpired 表示授权已过期，当前时间等于或晚于 ExpiresAt。
	LicenseStateExpired LicenseState = "expired"
)

func (s LicenseState) ShowText() string {
	switch s {
	case LicenseStateNotActivated:
		return "未激活"
	case LicenseStateNotYetValid:
		return "未生效"
	case LicenseStateExpired:
		return "已过期"
	case LicenseStateValid:
		return "有效"
	default:
		return ""
	}
}
