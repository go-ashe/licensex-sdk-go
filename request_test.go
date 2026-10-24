package licensex

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRequestJSONFormat 固定申请 JSON 的小驼峰字段名、设备信息和机器码输出。
func TestRequestJSONFormat(t *testing.T) {
	request, err := GenerateRequest(" RCS100 ", " 1.0.0\n", "{123E4567-E89B-12D3-A456-426614174000}")
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{
  "schemaVersion": 1,
  "productId": "RCS100",
  "productVersion": "1.0.0",
  "machine": {
    "algorithm": "dmi-uuid-sha256-v1",
    "machineCode": "v1:7882e7f37401fafe0514d8b41bebb1cede970d047ad25f7628ed0457d9e06170"
  }
}
`
	if string(data) != want {
		t.Fatalf("request JSON = %s; want %s", data, want)
	}
	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != request {
		t.Fatalf("JSON round trip = %+v, %v; want %+v", decoded, err, request)
	}
}

// TestMarshalRequestRejectsInvalidData 手动构造或修改后的申请也必须通过校验和文件大小检查。
func TestMarshalRequestRejectsInvalidData(t *testing.T) {
	valid, err := GenerateRequest("RCS100", "1.0", "123e4567-e89b-12d3-a456-426614174000")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Request){
		"schema":    func(r *Request) { r.SchemaVersion = 2 },
		"product":   func(r *Request) { r.ProductID = " " },
		"version":   func(r *Request) { r.ProductVersion = "" },
		"algorithm": func(r *Request) { r.Machine.Algorithm = "unknown" },
		"prefix":    func(r *Request) { r.Machine.MachineCode = "v2:" + strings.Repeat("a", 64) },
		"length":    func(r *Request) { r.Machine.MachineCode = "v1:abc" },
		"hex":       func(r *Request) { r.Machine.MachineCode = "v1:" + strings.Repeat("g", 64) },
		"size":      func(r *Request) { r.ProductVersion = strings.Repeat("a", MaxRequestSize) },
		// 输入未超限，JSON 转义后仍可能超过限制。
		"escaped size": func(r *Request) { r.ProductVersion = strings.Repeat("<", MaxRequestSize/2) },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			change(&request)
			if data, err := MarshalRequest(request); !errors.Is(err, ErrInvalidRequest) || data != nil {
				t.Fatalf("invalid request returned %d bytes, %v", len(data), err)
			}
		})
	}
}

// TestWriteRequest 验证文件可导入、不覆盖已有文件、无效申请不创建文件以及底层错误保留。
func TestWriteRequest(t *testing.T) {
	request, err := GenerateRequest("RCS100", "1.0", "123e4567-e89b-12d3-a456-426614174000")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "request.json")
	if err := WriteRequest(path, request); err != nil {
		t.Fatal(err)
	}
	want, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ProductVersion = "2.0"
	if err := WriteRequest(path, request); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwriting request returned %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, want) {
		t.Fatalf("existing file was changed: %q, %v", data, err)
	}
	invalidPath := filepath.Join(t.TempDir(), "invalid.json")
	if err := WriteRequest(invalidPath, Request{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid request returned %v", err)
	}
	if _, err := os.Stat(invalidPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid request created a file: %v", err)
	}
	if err := WriteRequest(filepath.Join(t.TempDir(), "missing", "request.json"), request); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing parent returned %v", err)
	}
}

// TestGenerateRequest 验证申请生成入口拒绝无效产品、版本和设备身份。
func TestGenerateRequest(t *testing.T) {
	tests := []struct {
		name           string
		productID      string
		productVersion string
		deviceUUID     string
		want           Request
		wantErr        error
		invalidUUID    bool
	}{
		{
			name:           "valid",
			productID:      "RCS100",
			productVersion: "1.0",
			deviceUUID:     "123e4567-e89b-12d3-a456-426614174000",
			want: Request{
				SchemaVersion:  SchemaVersion,
				ProductID:      "RCS100",
				ProductVersion: "1.0",
				Machine: Machine{
					Algorithm:   MachineAlgorithmDMIUUIDSHA256V1,
					MachineCode: "v1:7882e7f37401fafe0514d8b41bebb1cede970d047ad25f7628ed0457d9e06170",
				},
			},
		},
		{name: "empty product", productVersion: "1.0", deviceUUID: testUUID, wantErr: ErrInvalidRequest},
		{name: "blank product", productID: " \n", productVersion: "1.0", deviceUUID: testUUID, wantErr: ErrInvalidRequest},
		{name: "empty version", productID: "RCS100", deviceUUID: testUUID, wantErr: ErrInvalidRequest},
		{name: "invalid UTF-8", productID: "RCS100", productVersion: "1.\xff", deviceUUID: testUUID, wantErr: ErrInvalidRequest},
		{name: "oversize product", productID: strings.Repeat("a", MaxRequestSize+1), productVersion: "1.0", deviceUUID: testUUID, wantErr: ErrInvalidRequest},
		{name: "invalid UUID", productID: "RCS100", productVersion: "1.0", deviceUUID: "invalid", invalidUUID: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRequest(tt.productID, tt.productVersion, tt.deviceUUID)
			if tt.invalidUUID {
				if err == nil || got != (Request{}) {
					t.Fatalf("invalid UUID returned %+v, %v", got, err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GenerateRequest error = %v; want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("GenerateRequest = %+v; want %+v", got, tt.want)
			}
		})
	}
}
