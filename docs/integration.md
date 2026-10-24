# LicenseX Go SDK 接入手册

SDK 在业务服务内完成机器码生成、授权校验和本地存储。LicenseX 负责审批与签发，业务服务负责接口和功能、额度限制。申请与授权文件由业务服务或人工传递，SDK 不主动连接签发端。

接入顺序：**初始化 → 加载授权 → 导出申请 → 导入授权 → 业务检查与状态展示**。

## 1. 安装与准备

当前项目要求 Go 1.27.0。

```sh
go get github.com/go-ashe/licensex-sdk-go
```

从 LicenseX 产品管理取得产品标识、密钥编号和公钥 Base64。公钥必须是原始 Ed25519 公钥的标准 Base64，解码后为 32 字节。产品标识和公钥配置应由业务服务从可信配置加载。

## 2. 初始化与加载

每个产品与设备组合创建一个长期使用的 `Manager`。`NewManager()` 不读取授权文件，启动时需调用 `Load()`。

```go
package integration

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/go-ashe/licensex-sdk-go"
)

type Config struct {
	ProductID   string
	LicensePath string            // 例如 ./data/license/license.lic
	PubKeys     map[string]string // 密钥编号 → 公钥 Base64
	DeviceUUID  string            // 留空时自动采集
}

func InitManager(cfg Config) (*licensex.Manager, error) {
	keys, err := licensex.ParsePublicKeys(cfg.PubKeys)
	if err != nil {
		return nil, err
	}
	storage, err := licensex.NewFileStorage(cfg.LicensePath)
	if err != nil {
		return nil, err
	}
	manager, err := licensex.NewManager(licensex.ManagerOptions{
		ProductID:  cfg.ProductID,
		PubKeys:    keys,
		Storage:    storage,
		DeviceUUID: cfg.DeviceUUID,
	})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.LicensePath), 0o700); err != nil {
		return nil, err
	}
	if _, err := manager.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("加载授权失败：%v", err)
	}
	return manager, nil
}
```

示例允许未激活服务继续提供申请和导入入口；受控业务由 `Check()` 拦截。

| 配置 | 要求 |
| --- | --- |
| `ProductID` | 必填，与签发端一致，去除两端空白后区分大小写 |
| `PubKeys` | 至少一把公钥，密钥编号须与签发端一致 |
| `Storage` | 必填，可使用 `FileStorage` 或自定义实现 |
| `DeviceUUID` | 可选；自动采集支持 Linux DMI UUID 和 macOS IOPlatformUUID |
| `Now` | 可选，默认 `time.Now`；自定义时间源须并发安全且不能返回零时间 |

容器及其他系统应显式提供稳定、可信的部署设备 UUID。自动采集失败会返回错误，不生成随机身份。

| `Load()` 结果 | 行为 |
| --- | --- |
| 文件不存在 | 返回 `os.ErrNotExist`，清除内存授权，处于未激活状态 |
| 文件损坏、验签失败、产品或设备不匹配 | 返回错误，清除已有内存授权 |
| 授权有效、已过期或未生效 | 加载成功，返回对应状态；业务是否可用由 `Check()` 判断 |

## 3. 申请与导入

在最终部署设备上导出申请：

```go
package integration

import "github.com/go-ashe/licensex-sdk-go"

func ExportRequest(manager *licensex.Manager, version, path string) error {
	request, err := manager.Request(version)
	if err != nil {
		return err
	}
	return licensex.WriteRequest(path, request)
}
```

`version` 是当前软件版本。导出路径的父目录须已存在，已有文件不会被覆盖。需要通过 HTTP 下载时，使用 `MarshalRequest(request)` 获取 JSON 字节。

申请包含产品标识、版本和机器码，不包含原始 UUID。`manager.MachineCode()` 可用于页面展示和人工核对；申请本身未签名，签发资格由 LicenseX 审批。未激活或授权过期时仍可生成申请。

收到签发文件后，将完整原始字节传入 `manager.Import(data)`，并检查返回错误。授权文件包含 `payload` 和 `signature`，应原样传入。上传接口可使用 `io.ReadAll(io.LimitReader(reader, licensex.MaxLicenseSize+1))` 限制读取大小。

| `Import()` 结果 | 行为 |
| --- | --- |
| 验证并保存成功 | 替换文件和内存授权，立即使用新授权 |
| 验签失败、字段无效、产品或设备不匹配 | 返回错误，保留旧授权 |
| 已过期或尚未生效 | 返回对应错误，保留旧授权 |
| 保存失败 | 返回错误，保留旧授权 |

续期时重新签发并导入即可。新授权整体替换旧授权，功能和额度不合并。

## 4. 业务检查

每个受控业务入口调用 `Check()`。调用成功后，业务服务还需检查功能和实际用量，例如：

```go
package integration

import (
	"fmt"
	"slices"

	"github.com/go-ashe/licensex-sdk-go"
)

func CheckTransport(manager *licensex.Manager, totalRobots int) error {
	if totalRobots < 0 {
		return fmt.Errorf("机器人总量不能为负数")
	}
	payload, err := manager.Check()
	if err != nil {
		return err
	}
	if !slices.Contains(payload.Features, "transport") {
		return fmt.Errorf("授权未包含 transport 功能")
	}
	limit, ok := payload.Limits["robots"]
	if !ok || limit <= 0 || totalRobots > limit {
		return fmt.Errorf("机器人总量超出授权额度")
	}
	return nil
}
```

`totalRobots` 应为操作完成后的总量。未列出的功能和额度视为未授予；SDK 不统计或预占实际用量，业务服务应在事务或其他并发控制下完成额度检查和业务写入。

## 5. 状态展示与错误处理

`manager.Status()` 返回授权详情、`State` 和 `RemainingDays`。状态每次查询时重新计算，适合管理页面展示；业务准入使用 `Check()`。

| `LicenseState` 枚举 | JSON 值 | 含义 |
| --- | --- | --- |
| `LicenseStateNotActivated` | `not_activated` | 未加载或导入可信授权 |
| `LicenseStateNotYetValid` | `not_yet_valid` | 尚未达到生效时间 |
| `LicenseStateValid` | `valid` | 已生效且未过期 |
| `LicenseStateExpired` | `expired` | 已达到或超过截止时间 |

`status.State.ShowText()` 返回中文状态。未激活时，`Status()` 同时返回 `ErrNotActivated`，其余字段为零值；页面可识别此错误并展示未激活。已过期或未生效时，`Status()` 仍正常返回可信详情。

`RemainingDays` 为剩余天数，不足一天向上取整；永久授权为 `-1`，已过期为 `0`。是否可用应依据状态判断。授权生效区间为 `[issuedAt, expiresAt)`，永久授权仍需达到生效时间。

使用 `errors.Is()` 判断错误，保留底层错误链。

| 错误 | 处理方向 |
| --- | --- |
| `ErrNotActivated`、`os.ErrNotExist` | 提供申请和导入入口；文件缺失由 `Load()` 返回 `os.ErrNotExist` |
| `ErrExpired`、`ErrNotYetValid` | 拒绝受控业务，展示有效期 |
| `ErrWrongProduct`、`ErrWrongMachine` | 核对产品和部署设备 |
| `ErrUnknownKey`、`ErrBadSignature` | 核对受信公钥和原始授权文件 |
| `ErrMalformed`、`ErrUnsupported`、`ErrInvalidPayload` | 检查文件格式、结构版本和授权字段 |
| `ErrInvalidOptions`、`ErrInvalidRequest`、`ErrInvalidVerifyOptions` | 检查配置和调用参数 |

机器身份采集和存储操作还可能返回底层错误，调用方应处理所有非 nil 错误。

## 6. 部署与维护

- **存储**：申请导出和授权文件上限均为 1 MiB。`FileStorage` 通过权限为 `0600` 的临时文件原子替换目标，父目录需由业务服务创建。自定义 `Storage` 须保证保存失败时保留旧数据。
- **并发**：同一个 `Manager` 可并发使用，返回值与内部状态隔离。SDK 不监听文件变化，多进程共享存储时需协调更新并显式调用 `Load()`。
- **公钥轮换**：过渡期同时配置新旧密钥。配置变更后需重建 `Manager` 或重启服务，再加载授权。
- **离线限制**：SDK 不提供授权吊销、防旧授权回退或跨重启时间回拨检测。重新签发不会使其他位置的旧授权自动失效。

自行管理授权状态时，可使用 `Verify()` 校验签名、产品、设备及有效期；`VerifyStatus()` 允许展示已过期或未生效的授权。`ParsePayload()` 和 `ValidatePayload()` 不验签，不能单独作为业务准入依据。

字段及接口定义见 [types.go](../types.go)、[cons.go](../cons.go) 和 [errors.go](../errors.go)。
