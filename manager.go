package licensex

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// Manager 串行处理加载和导入，业务检查可并发读取已发布的授权。
// 必须通过 NewManager 创建；文件 I/O 和验签不会持有授权快照的读写锁。
// 每次 Check 都检查有效期，无后台任务；本身不提供跨重启时间回拨检测。
type Manager struct {
	productID   string
	machineCode string
	pubKeys     PublicKeys
	storage     Storage
	now         func() time.Time
	payload     *Payload

	updateMu sync.Mutex
	mu       sync.RWMutex
}

// NewManager 校验配置并确定设备身份，不读取已保存的授权。
// 受信公钥会被复制保存，调用方后续修改配置不会影响此实例。
// 启动时显式调用 Load；首次无授权时仍可生成申请并导入授权。
func NewManager(options ManagerOptions) (m *Manager, err error) {
	m = &Manager{
		productID: strings.TrimSpace(options.ProductID),
		storage:   options.Storage,
	}

	if err = validateRequestText("productId", m.productID); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}

	if options.Storage == nil || len(options.PubKeys) == 0 {
		return nil, fmt.Errorf("%w: storage and trusted keys are required", ErrInvalidOptions)
	}

	pubKeys := make(PublicKeys, len(options.PubKeys))
	for id, key := range options.PubKeys {
		if isBlank(id) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid trusted key", ErrInvalidOptions)
		}
		pubKeys[id] = bytes.Clone(key)
	}

	var code string
	if strings.TrimSpace(options.DeviceUUID) == "" {
		code, err = MachineCode(m.productID)
	} else {
		code, err = GenerateMachineCode(m.productID, options.DeviceUUID)
	}
	if err != nil {
		return nil, err
	}

	clock := options.Now
	if clock == nil {
		clock = time.Now
	}

	m.machineCode = code
	m.pubKeys = pubKeys
	m.now = clock
	return
}

// MachineCode 返回初始化时确定的当前产品机器码。
func (m *Manager) MachineCode() string {
	return m.machineCode
}

// Request 生成当前产品与设备的申请，不依赖授权是否存在或有效。
// productVersion 为生成申请时的软件版本，去除两端空白后必须为非空 UTF-8 文本。
func (m *Manager) Request(productVersion string) (Request, error) {
	productVersion = strings.TrimSpace(productVersion)
	if err := validateRequestProduct(m.productID, productVersion); err != nil {
		return Request{}, err
	}
	return Request{
		SchemaVersion:  SchemaVersion,
		ProductID:      m.productID,
		ProductVersion: productVersion,
		Machine: Machine{
			Algorithm:   MachineAlgorithmDMIUUIDSHA256V1,
			MachineCode: m.machineCode,
		},
	}, nil
}

// Load 读取并重新验签已保存的文件；过期或尚未生效时仍加载可信详情。
// 读取或验签失败时清除内存授权，后续 Check 拒绝业务。
func (m *Manager) Load() (result Status, err error) {
	m.updateMu.Lock()
	defer m.updateMu.Unlock()
	defer func() {
		if err != nil {
			m.publish(nil)
		}
	}()
	data, err := m.storage.Load()
	if err != nil {
		return Status{}, fmt.Errorf("licensex: load license: %w", err)
	}
	options, err := m.verifyOptions()
	if err != nil {
		return Status{}, err
	}
	status, err := VerifyStatus(data, m.pubKeys, options)
	if err != nil {
		return Status{}, err
	}
	payload := clonePayload(status.Payload)
	m.publish(&payload)
	return status, nil
}

// Import 完整验签并检查有效期，保存成功后才发布新授权。
// 任何验证或保存错误都保留原内存授权；Storage 必须满足原子保存约定。
func (m *Manager) Import(data []byte) (Status, error) {
	m.updateMu.Lock()
	defer m.updateMu.Unlock()
	if len(data) == 0 || len(data) > MaxLicenseSize {
		return Status{}, fmt.Errorf("%w: license file size", ErrMalformed)
	}
	options, err := m.verifyOptions()
	if err != nil {
		return Status{}, err
	}
	data = bytes.Clone(data)
	payload, err := Verify(data, m.pubKeys, options)
	if err != nil {
		return Status{}, err
	}
	if err := m.storage.Save(data); err != nil {
		return Status{}, fmt.Errorf("licensex: save license: %w", err)
	}
	m.publish(&payload)
	return statusFor(clonePayload(payload), options.CurrentTime), nil
}

// Status 返回当前时间的可信授权详情；无授权时返回 LicenseStateNotActivated 和 ErrNotActivated。
// 每次调用都会按当前时间重新计算状态和剩余天数，适合供前端查询展示。
// 过期或尚未生效时仍返回详情。返回的 map、slice 和时间指针与内部状态隔离。
func (m *Manager) Status() (Status, error) {
	payload := m.snapshot()
	if payload == nil {
		return Status{State: LicenseStateNotActivated}, ErrNotActivated
	}
	now, err := m.currentTime()
	if err != nil {
		return Status{}, err
	}
	return statusFor(clonePayload(*payload), now), nil
}

// Check 用于每个受授权控制的业务入口；失败时不返回可用权益。
// 成功后接入方仍需按 Limits 和 Features 执行具体业务限制。
func (m *Manager) Check() (Payload, error) {
	payload := m.snapshot()
	if payload == nil {
		return Payload{}, ErrNotActivated
	}
	now, err := m.currentTime()
	if err != nil {
		return Payload{}, err
	}
	switch stateAt(*payload, now) {
	case LicenseStateValid:
		return clonePayload(*payload), nil
	case LicenseStateNotYetValid:
		return Payload{}, ErrNotYetValid
	case LicenseStateExpired:
		return Payload{}, ErrExpired
	default:
		return Payload{}, ErrNotActivated
	}
}

// snapshot 在读锁保护下取得内部授权指针；未加载授权时返回 nil。
// 发布后不再修改 Payload；调用方只取得副本，因此可在释放读锁后安全读取。
func (m *Manager) snapshot() *Payload {
	m.mu.RLock()
	payload := m.payload
	m.mu.RUnlock()
	return payload
}

// publish 在写锁保护下替换当前授权；nil 表示清除授权。
// 保存后调用方不得继续修改 payload 及其引用的数据。
func (m *Manager) publish(payload *Payload) {
	m.mu.Lock()
	m.payload = payload
	m.mu.Unlock()
}

// verifyOptions 使用固定的产品、机器码和本次校验时间构造验签参数。
func (m *Manager) verifyOptions() (VerifyOptions, error) {
	now, err := m.currentTime()
	if err != nil {
		return VerifyOptions{}, err
	}
	return VerifyOptions{ProductID: m.productID, MachineCode: m.machineCode, CurrentTime: now}, nil
}

// currentTime 读取配置的时间源；返回零时间时报告 ErrInvalidOptions。
func (m *Manager) currentTime() (time.Time, error) {
	now := m.now()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrInvalidOptions)
	}
	return now, nil
}

// clonePayload 复制授权中的 map、slice 和时间指针，隔离调用方与内部状态。
func clonePayload(payload Payload) Payload {
	payload.Limits = maps.Clone(payload.Limits)
	payload.Features = slices.Clone(payload.Features)
	if payload.ExpiresAt != nil {
		value := *payload.ExpiresAt
		payload.ExpiresAt = &value
	}
	if payload.PublishedAt != nil {
		value := *payload.PublishedAt
		payload.PublishedAt = &value
	}
	return payload
}
