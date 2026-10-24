package licensex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateMachineCodeLicenseXCompatibility 验证机器码兼容 LicenseX v1，且绑定产品标识。
func TestGenerateMachineCodeLicenseXCompatibility(t *testing.T) {
	// 固定 LicenseX v1 的既有结果，防止算法或规范化方式变化导致授权失效。
	const want = "v1:7882e7f37401fafe0514d8b41bebb1cede970d047ad25f7628ed0457d9e06170"
	// 标准格式、大小写和两端空白、外层花括号均应规范化为相同 UUID。
	// 产品标识两端的空白也应被去除，不影响既有机器码。
	for _, uuid := range []string{
		"123e4567-e89b-12d3-a456-426614174000",
		" 123E4567-E89B-12D3-A456-426614174000\n",
		"{123E4567-E89B-12D3-A456-426614174000}",
	} {
		code, err := GenerateMachineCode(" RCS100 ", uuid)
		if err != nil || code != want {
			t.Errorf("GenerateMachineCode(%q) = %q, %v; want %q", uuid, code, err, want)
		}
	}
	// 更换产品或仅改变产品标识的大小写，都不能复用原产品的机器码。
	for _, product := range []string{"other-product", "rcs100"} {
		code, err := GenerateMachineCode(product, "123e4567-e89b-12d3-a456-426614174000")
		if err != nil || code == want {
			t.Errorf("product %q must have a distinct machine code: %q, %v", product, code, err)
		}
	}
}

// TestGenerateMachineCodeRejectsInvalidInput 验证无效输入返回错误及空机器码，不生成替代身份。
func TestGenerateMachineCodeRejectsInvalidInput(t *testing.T) {
	// 覆盖空值、非 UUID、缺少连字符、占位值、非法十六进制字符、长度和分隔符错误。
	for _, uuid := range []string{
		"", "not-a-uuid", "123e4567e89b12d3a456426614174000",
		"00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
		"g23e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-42661417400",
		"123e4567_e89b-12d3-a456-426614174000",
	} {
		if code, err := GenerateMachineCode("RCS100", uuid); err == nil || code != "" {
			t.Errorf("invalid UUID %q returned %q, %v", uuid, code, err)
		}
	}
	// 手动生成和自动采集两个入口都必须拒绝仅包含空白的产品标识。
	if code, err := GenerateMachineCode(" \n", "123e4567-e89b-12d3-a456-426614174000"); err == nil || code != "" {
		t.Fatalf("empty product returned %q, %v", code, err)
	}
	if code, err := MachineCode(" \n"); err == nil || code != "" {
		t.Fatalf("empty product returned %q, %v", code, err)
	}
}

// TestReadDeviceUUIDFiles 验证 UUID 文件读取、候选路径回退及底层错误保留。
func TestReadDeviceUUIDFiles(t *testing.T) {
	// 使用临时文件模拟系统路径，避免测试依赖执行机器的硬件或权限。
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	valid := filepath.Join(dir, "valid")
	const want = "123e4567-e89b-12d3-a456-426614174000"
	// 模拟系统文件常见的大写 UUID 和行尾换行，结果应规范化为小写。
	if err := os.WriteFile(valid, []byte(strings.ToUpper(want)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// 空文件、无效内容以及超过 256 字节上限的文件都不能作为设备身份。
	for _, data := range []string{"", "invalid", strings.Repeat("a", 257)} {
		invalid := filepath.Join(dir, "invalid")
		if err := os.WriteFile(invalid, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		// 前面的候选文件不存在或内容无效时，应继续读取后续有效路径。
		if uuid, err := readDeviceUUIDFiles(missing, invalid, valid); err != nil || uuid != want {
			t.Errorf("fallback returned %q, %v; want %q", uuid, err, want)
		}
		// 没有有效候选路径时，应返回错误及空 UUID。
		if uuid, err := readDeviceUUIDFiles(invalid); err == nil || uuid != "" {
			t.Errorf("invalid file returned %q, %v", uuid, err)
		}
	}
	// 包装后的错误仍需支持 errors.Is，便于调用方识别文件不存在。
	if uuid, err := readDeviceUUIDFiles(missing); uuid != "" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file returned %q, %v", uuid, err)
	}
}

// TestParsePlatformUUID 验证 macOS ioreg 输出中的 UUID 提取、规范化和异常处理。
func TestParsePlatformUUID(t *testing.T) {
	const want = "123e4567-e89b-12d3-a456-426614174000"
	// 模拟带树形缩进的 ioreg 输出，应准确提取 IOPlatformUUID 并转为小写。
	output := "+-o Root\n  | {\n  |   \"IOPlatformUUID\" = \"123E4567-E89B-12D3-A456-426614174000\"\n  | }"
	if uuid, err := parsePlatformUUID(output); err != nil || uuid != want {
		t.Fatalf("parsePlatformUUID returned %q, %v; want %q", uuid, err, want)
	}
	// 缺少目标属性、空值、未加引号的值或全零 UUID 都必须报错。
	// 其他属性即使包含有效 UUID，也不能被误当作硬件身份。
	for _, output := range []string{
		"", `"OtherProperty" = "123e4567-e89b-12d3-a456-426614174000"`,
		`"IOPlatformUUID" = ""`, `"IOPlatformUUID" = invalid`,
		`"IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"`,
	} {
		if uuid, err := parsePlatformUUID(output); err == nil || uuid != "" {
			t.Errorf("invalid ioreg output returned %q, %v", uuid, err)
		}
	}
}

// TestMachineCode 显式启用时采集真实硬件，避免常规测试依赖宿主机环境。
// 使用 LICENSEX_TEST_HARDWARE=1 go test -v -run '^TestMachineCode$' -count=1 查看实时采集结果。
func TestMachineCode(t *testing.T) {
	if os.Getenv("LICENSEX_TEST_HARDWARE") != "1" {
		t.Skip("set LICENSEX_TEST_HARDWARE=1 to test real hardware UUID collection")
	}
	const productID = "rcs100"
	got, err := MachineCode(productID)
	if err != nil {
		t.Fatal(err)
	}
	if !isValidBinding(Machine{Algorithm: MachineAlgorithmDMIUUIDSHA256V1, MachineCode: got}) {
		t.Fatalf("invalid machine code: %q", got)
	}
	t.Logf("产品 %s 的本机机器码：%s", productID, got)
}
