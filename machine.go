package licensex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// MachineCode 读取本机硬件 UUID，并生成绑定产品的机器码。
// Linux 使用 DMI UUID，macOS 使用 IOPlatformUUID；其他系统返回错误。
// 采集失败时不生成默认或随机身份。返回值不包含原始 UUID。
func MachineCode(productID string) (string, error) {
	if strings.TrimSpace(productID) == "" {
		return "", errors.New("licensex: empty product")
	}
	uuid, err := readDeviceUUID()
	if err != nil {
		return "", err
	}
	return GenerateMachineCode(productID, uuid)
}

// GenerateMachineCode 根据产品标识和设备 UUID 生成 LicenseX v1 机器码。
// UUID 使用 8-4-4-4-12 十六进制格式，允许大小写、两端空白及外层花括号；
// 全零、全 f 或格式无效的 UUID 会被拒绝。productID 去除两端空白后区分大小写。
// 机器码 = "v1:" + hex(SHA256(产品标识 + "\x00" + 规范化后的设备 UUID))
func GenerateMachineCode(productID, deviceUUID string) (string, error) {
	productID = strings.TrimSpace(productID)
	if productID == "" {
		return "", errors.New("licensex: empty product")
	}
	uuid, err := normalizeDeviceUUID(deviceUUID)
	if err != nil {
		return "", err
	}
	// 与 LicenseX 一致：产品标识 + NUL + 规范化 UUID，计算 SHA-256。
	digest := sha256.Sum256([]byte(productID + "\x00" + uuid))
	return "v1:" + hex.EncodeToString(digest[:]), nil
}

// normalizeDeviceUUID 将设备 UUID 去除两端空白及外层花括号，并转换为小写。
// 格式无效、全零或全 f 的 UUID 会返回错误。
func normalizeDeviceUUID(value string) (string, error) {
	uuid := strings.ToLower(strings.TrimSpace(value))
	if len(uuid) == 38 && uuid[0] == '{' && uuid[37] == '}' {
		uuid = uuid[1:37]
	}
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return "", errors.New("licensex: invalid device UUID format")
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil || len(decoded) != 16 {
		return "", errors.New("licensex: invalid device UUID format")
	}
	if uuid == "00000000-0000-0000-0000-000000000000" || uuid == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return "", errors.New("licensex: invalid device UUID value")
	}
	return uuid, nil
}

// readDeviceUUID 按操作系统采集并校验硬件 UUID；macOS 命令最多执行 5 秒。
// 不支持的系统或采集失败时返回错误，不生成替代身份。
func readDeviceUUID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return readDeviceUUIDFiles("/sys/class/dmi/id/product_uuid", "/sys/devices/virtual/dmi/id/product_uuid")
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		data, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			return "", fmt.Errorf("licensex: read macOS hardware UUID: %w", err)
		}
		return parsePlatformUUID(string(data))
	default:
		return "", fmt.Errorf("licensex: automatic hardware UUID collection is unsupported on %s; use GenerateMachineCode with an explicit UUID", runtime.GOOS)
	}
}

// readDeviceUUIDFiles 按顺序读取候选路径，返回第一个有效的设备 UUID。
// 全部失败时合并各路径的错误，保留底层错误供 errors.Is 判断。
func readDeviceUUIDFiles(paths ...string) (string, error) {
	var failures []error
	for _, path := range paths {
		uuid, err := readDeviceUUIDFile(path)
		if err == nil {
			return uuid, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", path, err))
	}
	return "", fmt.Errorf("licensex: read hardware UUID: %w", errors.Join(failures...))
}

// readDeviceUUIDFile 从指定文件限长读取并规范化设备 UUID，最多接受 256 字节。
func readDeviceUUIDFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	const maxSize = 256
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSize {
		return "", errors.New("hardware UUID file exceeds 256 bytes")
	}
	return normalizeDeviceUUID(string(data))
}

// parsePlatformUUID 从 macOS ioreg 输出中提取并规范化 IOPlatformUUID。
// 缺少目标属性、字符串格式错误或 UUID 无效时返回错误。
func parsePlatformUUID(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimLeft(line, " \t|"), "=")
		if !ok || strings.TrimSpace(key) != `"IOPlatformUUID"` {
			continue
		}
		uuid, err := strconv.Unquote(strings.TrimSpace(value))
		if err != nil {
			return "", fmt.Errorf("licensex: invalid IOPlatformUUID encoding: %w", err)
		}
		return normalizeDeviceUUID(uuid)
	}
	return "", errors.New("licensex: ioreg did not return IOPlatformUUID")
}
