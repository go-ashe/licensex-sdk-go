# licensex-sdk-go

LicenseX Go SDK，用于生成机器授权申请、导入授权和检查授权状态。SDK 在本地校验授权，不主动连接签发端。

完整示例见 [SDK 接入手册](docs/integration.md)。

安装：

```sh
go get github.com/go-ashe/licensex-sdk-go
```

接入时，从 LicenseX 产品管理取得产品标识、密钥编号和公钥 Base64。
使用 `ParsePublicKeys()` 解析公钥、`NewFileStorage()` 指定存储位置，再通过 `NewManager()` 创建管理器。
`DeviceUUID` 留空时自动采集设备 UUID，支持 Linux 和 macOS；存储目录需提前创建。

| 步骤 | 调用 | 说明 |
| --- | --- | --- |
| 启动加载 | `manager.Load()` | 加载已有授权；首次无文件时可继续提供申请和导入入口 |
| 展示机器码 | `manager.MachineCode()` | 用于设备登记和人工核对 |
| 生成申请 | `manager.Request("1.0.0")` | 传入当前软件版本 |
| 导出申请 | `licensex.MarshalRequest(request)` | 返回 JSON 字节，交给 LicenseX 审批签发 |
| 导入授权 | `manager.Import(data)` | 传入完整授权文件字节，校验通过后自动保存 |
| 业务检查 | `manager.Check()` | 每个受控业务入口调用，并按返回的功能和额度限制业务 |
| 查看状态 | `manager.Status()` | 获取授权状态、剩余天数和授权详情 |

授权状态类型为 `LicenseState`：

| 枚举 | 含义 |
| --- | --- |
| `LicenseStateNotActivated` | 未激活 |
| `LicenseStateNotYetValid` | 未生效 |
| `LicenseStateValid` | 有效 |
| `LicenseStateExpired` | 已过期 |

`state.ShowText()` 返回中文状态。未激活时，`Status()` 同时返回 `ErrNotActivated`。
`remainingDays` 为剩余天数，不足一天向上取整；永久授权为 `-1`，已到期为 `0`，未激活时为零值。
