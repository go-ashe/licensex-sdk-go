# LicenseX SDK for Go

[![English](https://img.shields.io/badge/English-switch_language-555555?style=for-the-badge)](README.md)
[![简体中文](https://img.shields.io/badge/简体中文-当前语言-1677ff?style=for-the-badge)](README-CN.md)

## 关于

LicenseX Go SDK 为 Go 应用提供绑定设备的离线授权管理能力，用于生成授权申请、校验 Ed25519 签名、本地保存授权，以及在业务入口检查授权有效性。

- 根据产品标识和设备 UUID 生成机器码，将授权绑定到指定产品与设备。
- 支持试用、永久和限时授权。
- 导入并保存签名授权，提供授权状态、剩余天数、功能和额度信息。
- 在本地完成授权校验，不主动连接 LicenseX 签发端。申请传递、审批和授权交付由 SDK 外部流程完成。

## 运行环境

- Go **1.27.0 及以上**，以 [go.mod](go.mod) 为准。
- 自动采集设备 UUID 支持 Linux（DMI UUID）和 macOS（IOPlatformUUID）。
- 容器、其他系统或无法自动采集的部署环境，可通过 `ManagerOptions.DeviceUUID` 显式传入稳定、可信的部署设备 UUID。自动采集失败会返回错误，不生成随机身份作为替代。

## 安装方法

```sh
go get github.com/go-ashe/licensex-sdk-go
```

在代码中引入 SDK，包名为 `licensex`：

```go
import "github.com/go-ashe/licensex-sdk-go"
```

## 快速使用

从 LicenseX 产品管理取得**产品标识**、**密钥编号**和**公钥 Base64**。公钥必须是原始 32 字节 Ed25519 公钥的标准 Base64 编码，不接受 PEM 或 X.509 格式。

接入顺序为：**初始化 → 加载授权 → 导出申请 → 导入授权 → 业务检查**。每个产品与设备组合创建一个长期使用的 `Manager`。

### 初始化并加载授权

以下示例从环境变量读取可信配置。运行前设置 `LICENSEX_PRODUCT_ID`、`LICENSEX_KEY_ID` 和 `LICENSEX_PUBLIC_KEY_BASE64`。`LICENSEX_DEVICE_UUID` 为可选项，留空时自动采集本机设备 UUID。

```go
package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/go-ashe/licensex-sdk-go"
)

func main() {
	keys, err := licensex.ParsePublicKeys(map[string]string{
		os.Getenv("LICENSEX_KEY_ID"): os.Getenv("LICENSEX_PUBLIC_KEY_BASE64"),
	})
	if err != nil {
		log.Fatal(err)
	}

	path := filepath.Join("data", "license", "license.lic")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Fatal(err)
	}
	storage, err := licensex.NewFileStorage(path)
	if err != nil {
		log.Fatal(err)
	}
	manager, err := licensex.NewManager(licensex.ManagerOptions{
		ProductID:  os.Getenv("LICENSEX_PRODUCT_ID"),
		PubKeys:    keys,
		Storage:    storage,
		DeviceUUID: os.Getenv("LICENSEX_DEVICE_UUID"),
	})
	if err != nil {
		log.Fatal(err)
	}

	if _, err := manager.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("加载授权失败：%v", err)
	}
	log.Printf("机器码：%s", manager.MachineCode())
	if _, err := manager.Check(); err != nil {
		log.Printf("受控业务不可用：%v", err)
		return
	}
	log.Print("授权有效")
}
```

`NewManager()` 不读取已有授权，启动时需要显式调用 `Load()`。首次使用时没有授权文件属于正常情况。常驻服务可继续提供申请和导入入口，通过 `Check()` 拦截受控业务。

### 导出授权申请

以下片段使用前面初始化的 `manager`，放在应用的函数中执行。请在最终部署设备上生成申请：

```go
request, err := manager.Request("1.0.0")
if err != nil {
	return err
}
if err := licensex.WriteRequest("request.json", request); err != nil {
	return err
}
```

将 `request.json` 提交给 LicenseX 审批签发。版本参数是当前应用的软件版本。申请包含产品标识、版本和机器码，不包含原始设备 UUID。申请本身未签名，签发资格由 LicenseX 审批。未激活或授权过期时仍可生成申请。

`WriteRequest()` 要求父目录已存在，且不会覆盖已有文件。通过 HTTP 提供下载时，可使用 `licensex.MarshalRequest(request)` 获取 JSON 字节。

### 导入签名授权

将完整的原始授权文件传入 `Import()`：

```go
data, err := os.ReadFile("issued-license.lic")
if err != nil {
	return err
}
status, err := manager.Import(data)
if err != nil {
	return err
}
log.Printf("已导入授权 %s，状态：%s", status.LicenseID, status.State)
```

导入时依次检查签名、字段、产品、设备和有效期，保存成功后才更新内存授权。续期时导入新签发的文件即可，新授权会整体替换旧授权，包括功能和额度。

HTTP 上传接口可使用 `io.ReadAll(io.LimitReader(reader, licensex.MaxLicenseSize+1))` 限制读取大小，并拒绝超过 `MaxLicenseSize` 的数据。将包含 `payload` 和 `signature` 的原始授权文件整体传入 `Import()`。

### 检查业务授权

每个受控业务入口都应调用 `Check()`，成功后再由业务代码执行功能和额度限制。例如：

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

这里的 `totalRobots` 是操作完成后的总量。未列出的功能和额度视为未授予。SDK 不统计或预占实际用量，业务服务应在事务或其他并发控制下完成额度检查和业务写入。

### 查询授权状态

```go
status, err := manager.Status()
if err != nil && !errors.Is(err, licensex.ErrNotActivated) {
	return err
}
log.Printf("状态：%s，剩余天数：%d", status.State, status.RemainingDays)
```

`Status()` 每次调用都会重新计算状态，已过期或尚未生效的授权仍可返回可信详情。未激活时，同时返回 `LicenseStateNotActivated` 和 `ErrNotActivated`，其他字段为零值。业务准入使用 `Check()`。

| 状态枚举 | JSON 值 | 含义 |
| --- | --- | --- |
| `LicenseStateNotActivated` | `not_activated` | 未加载或导入可信授权 |
| `LicenseStateNotYetValid` | `not_yet_valid` | 尚未达到生效时间 |
| `LicenseStateValid` | `valid` | 已生效且未过期 |
| `LicenseStateExpired` | `expired` | 已达到或超过截止时间 |

`RemainingDays` 为剩余天数，不足一天向上取整；永久授权为 `-1`，已过期为 `0`。授权有效区间为 `[issuedAt, expiresAt)`，永久授权仍需达到生效时间。`status.State.ShowText()` 返回中文状态文案，其他语言可根据状态值自行翻译。

## 配置说明

| `ManagerOptions` 字段 | 说明 |
| --- | --- |
| `ProductID` | 必填。与签发端产品标识一致，去除两端空白后区分大小写。 |
| `PubKeys` | 必填。至少一把受信公钥，以签发端的密钥编号索引；使用 `ParsePublicKeys()` 解析 Base64 配置。 |
| `Storage` | 必填。通过 `NewFileStorage(path)` 创建，或自行实现 `Storage` 接口。 |
| `DeviceUUID` | 可选。留空时自动采集；显式提供时使用稳定的 `8-4-4-4-12` 十六进制 UUID，不接受全零或全 `f` 的 UUID。 |
| `Now` | 可选。默认使用 `time.Now`；自定义时间源必须可信、并发安全，且不能返回零时间。 |

## 错误处理

使用 `errors.Is()` 判断错误，包括被包装的文件系统错误。

| 错误 | 处理建议 |
| --- | --- |
| `ErrNotActivated`、`os.ErrNotExist` | 提供申请导出和授权导入入口；无文件时 `Load()` 返回 `os.ErrNotExist`。 |
| `ErrExpired`、`ErrNotYetValid` | 拒绝受控业务，展示授权有效期。 |
| `ErrWrongProduct`、`ErrWrongMachine` | 核对产品标识和部署设备。 |
| `ErrUnknownKey`、`ErrBadSignature` | 核对受信公钥和原始签名文件。 |
| `ErrMalformed`、`ErrUnsupported`、`ErrInvalidPayload` | 检查文件格式、结构版本和授权字段。 |
| `ErrInvalidOptions`、`ErrInvalidRequest`、`ErrInvalidVerifyOptions` | 检查配置和调用参数。 |

机器身份采集和存储操作还可能返回底层错误，调用方应处理所有非 nil 错误。

## 注意事项

- **加载与导入**：`Load()` 允许加载真实可信的已过期或未生效授权，供页面展示详情；读取或验证失败会清除内存授权。`Import()` 拒绝已过期或未生效的授权，验证或保存失败时保留旧授权。
- **存储**：申请 JSON 和授权文件上限各为 1 MiB，使用前需创建父目录。`FileStorage` 通过权限为 `0600` 的临时文件原子替换授权；自定义 `Storage.Save()` 必须在失败时保留旧数据。
- **并发**：同一个 `Manager` 可并发使用，返回值与内部状态隔离。SDK 不监听文件变化，多进程共享存储时需协调更新，并按需显式调用 `Load()`。
- **公钥轮换**：过渡期同时配置新旧受信公钥。配置变更后需重建管理器或重启服务，再加载授权。
- **离线运行**：SDK 不提供授权吊销、防旧授权回退或跨重启时间回拨检测。重新签发不会使其他位置的旧授权自动失效。
- **直接验签**：自行管理授权状态时可使用 `Verify()`；需要展示已过期或未生效授权时使用 `VerifyStatus()`。`ParsePayload()` 和 `ValidatePayload()` 不验签，不能单独作为业务准入依据。

## 文档与支持

- [类型与配置](types.go)、[常量与状态](cons.go)、[错误定义](errors.go)
- [反馈问题](https://github.com/go-ashe/licensex-sdk-go/issues)

## 许可证

本项目采用 [MIT License](LICENSE)。
