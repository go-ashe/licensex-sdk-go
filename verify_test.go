package licensex

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

const testUUID = "123e4567-e89b-12d3-a456-426614174000"

// testPayload 构造绑定固定产品和设备、在测试时间有效的试用授权载荷。
func testPayload(t *testing.T) Payload {
	t.Helper()
	code, err := GenerateMachineCode("RCS100", testUUID)
	if err != nil {
		t.Fatal(err)
	}
	expires := testNow.Add(24 * time.Hour)
	published := testNow.Add(-time.Hour)
	return Payload{
		SchemaVersion: SchemaVersion, LicenseID: "license-1", KeyID: "test-key", Product: "RCS100",
		CustomerID: "customer-1", ProjectID: "project-1", Type: TypeTrial,
		IssuedAt: published, PublishedAt: &published, ExpiresAt: &expires,
		Machine: Machine{Algorithm: MachineAlgorithmDMIUUIDSHA256V1, MachineCode: code},
		Limits:  map[string]int{"robots": 10}, Features: []string{"transport"},
	}
}

// testPrivateKey 从固定种子生成可复现的 Ed25519 私钥，仅用于测试。
func testPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
}

// testKeys 返回与测试私钥对应的受信公钥映射。
func testKeys() PublicKeys {
	return PublicKeys{"test-key": testPrivateKey().Public().(ed25519.PublicKey)}
}

// testSignRaw 对原始 JSON 字节签名，以覆盖非规范 JSON 格式及无效字段。
func testSignRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	file, err := json.Marshal(Envelope{
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(testPrivateKey(), raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// testSign 将载荷编码为带缩进的 JSON，再签名并封装为测试授权文件。
func testSign(t *testing.T, payload Payload) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return testSignRaw(t, raw)
}

// testOptions 根据载荷的产品、机器码和固定测试时间构造验签参数。
func testOptions(payload Payload) VerifyOptions {
	return VerifyOptions{ProductID: payload.Product, MachineCode: payload.Machine.MachineCode, CurrentTime: testNow}
}

// TestVerifySignedLicense 验证原始载荷字节的签名，并确认验签后载荷内容保持一致。
func TestVerifySignedLicense(t *testing.T) {
	payload := testPayload(t)
	// 缩进后的原始字节参与验签，不能将解析结果重新编码后验签。
	got, err := Verify(testSign(t, payload), testKeys(), testOptions(payload))
	if err != nil || !reflect.DeepEqual(got, payload) {
		t.Fatalf("Verify = %+v, %v; want %+v", got, err, payload)
	}
}

// TestVerifyCamelCaseLicense 验证使用小驼峰字段和 machine 对象签发的完整授权文件。
func TestVerifyCamelCaseLicense(t *testing.T) {
	const raw = `{
		"schemaVersion": 1,
		"licenseId": "license-1",
		"keyId": "test-key",
		"product": "RCS100",
		"customerId": "customer-1",
		"projectId": "project-1",
		"machine": {
			"algorithm": "dmi-uuid-sha256-v1",
			"machineCode": "v1:7882e7f37401fafe0514d8b41bebb1cede970d047ad25f7628ed0457d9e06170"
		},
		"type": "trial",
		"issuedAt": "2026-10-21T23:00:00Z",
		"publishedAt": "2026-10-21T23:00:00Z",
		"expiresAt": "2026-10-23T00:00:00Z",
		"limits": {"robots": 10},
		"features": ["transport"]
	}`
	want := testPayload(t)
	got, err := Verify(testSignRaw(t, []byte(raw)), testKeys(), testOptions(want))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("camelCase license = %+v, %v; want %+v", got, err, want)
	}
}

// TestVerifyTimeBoundaries 验证生效与到期边界、永久授权和剩余天数向上取整。
func TestVerifyTimeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		typeName  string
		issuedIn  time.Duration
		expiresIn time.Duration
		state     LicenseState
		days      int64
		wantErr   error
	}{
		{"issued exactly now", TypeTrial, 0, time.Hour, LicenseStateValid, 1, nil},
		{"future", TypeTrial, time.Nanosecond, 24 * time.Hour, LicenseStateNotYetValid, 1, ErrNotYetValid},
		{"expiry in one ns", TypeTimeLimited, -time.Hour, time.Nanosecond, LicenseStateValid, 1, nil},
		{"expiry exactly now", TypeTrial, -time.Hour, 0, LicenseStateExpired, 0, ErrExpired},
		{"expired", TypeTrial, -time.Hour, -time.Nanosecond, LicenseStateExpired, 0, ErrExpired},
		{"ceil days", TypeTimeLimited, -time.Hour, 24*time.Hour + time.Nanosecond, LicenseStateValid, 2, nil},
		{"perpetual", TypePerpetual, -time.Hour, 0, LicenseStateValid, -1, nil},
		{"perpetual future", TypePerpetual, time.Nanosecond, 0, LicenseStateNotYetValid, -1, ErrNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := testPayload(t)
			payload.Type = tc.typeName
			payload.IssuedAt = testNow.Add(tc.issuedIn)
			expires := testNow.Add(tc.expiresIn)
			payload.ExpiresAt = &expires
			if tc.typeName == TypePerpetual {
				payload.ExpiresAt = nil
			}
			file := testSign(t, payload)
			got, err := Verify(file, testKeys(), testOptions(payload))
			if !errors.Is(err, tc.wantErr) || (err != nil && !reflect.DeepEqual(got, Payload{})) {
				t.Fatalf("Verify = %+v, %v; want %v", got, err, tc.wantErr)
			}
			if err == nil && !reflect.DeepEqual(got, payload) {
				t.Fatalf("Verify returned different rights: %+v; want %+v", got, payload)
			}
			status, err := VerifyStatus(file, testKeys(), testOptions(payload))
			if err != nil || status.State != tc.state || status.LicenseID != payload.LicenseID {
				t.Fatalf("VerifyStatus = %+v, %v", status, err)
			}
			if status.RemainingDays != tc.days {
				t.Fatalf("remaining days = %v; want %d", status.RemainingDays, tc.days)
			}
		})
	}
}

// TestVerifyRejectsUntrustedData 验证篡改、未知密钥、错误公钥及产品或设备不匹配时拒绝授权。
func TestVerifyRejectsUntrustedData(t *testing.T) {
	payload := testPayload(t)
	file := testSign(t, payload)
	var envelope Envelope
	if err := json.Unmarshal(file, &envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte("license-1"), []byte("license-2"), 1))
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		file    []byte
		keys    PublicKeys
		options VerifyOptions
		wantErr error
	}{
		{"tampered", tampered, testKeys(), testOptions(payload), ErrBadSignature},
		{"unknown key", file, nil, testOptions(payload), ErrUnknownKey},
		{"invalid key length", file, PublicKeys{"test-key": {1}}, testOptions(payload), ErrBadSignature},
		{"wrong key", file, PublicKeys{"test-key": make(ed25519.PublicKey, ed25519.PublicKeySize)}, testOptions(payload), ErrBadSignature},
		{"wrong product", file, testKeys(), VerifyOptions{ProductID: "other", MachineCode: payload.Machine.MachineCode}, ErrWrongProduct},
		{"wrong machine", file, testKeys(), VerifyOptions{ProductID: payload.Product, MachineCode: "other"}, ErrWrongMachine},
		{"empty options", file, testKeys(), VerifyOptions{}, ErrInvalidVerifyOptions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Verify(tc.file, tc.keys, tc.options)
			if !errors.Is(err, tc.wantErr) || !reflect.DeepEqual(got, Payload{}) {
				t.Fatalf("Verify = %+v, %v; want %v", got, err, tc.wantErr)
			}
			status, err := VerifyStatus(tc.file, tc.keys, tc.options)
			if !errors.Is(err, tc.wantErr) || !reflect.DeepEqual(status, Status{}) {
				t.Fatalf("VerifyStatus exposed untrusted data: %+v, %v", status, err)
			}
		})
	}
}

// TestVerifyRejectsMalformedFile 验证空文件、超长数据、无效编码、未知字段和尾随内容被拒绝。
func TestVerifyRejectsMalformedFile(t *testing.T) {
	payload := testPayload(t)
	file := testSign(t, payload)
	var envelope Envelope
	if err := json.Unmarshal(file, &envelope); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string][]byte{
		"empty": nil,
		"size":  bytes.Repeat([]byte{' '}, MaxLicenseSize+1),
		"null":  []byte(`null`),
		// 以完整有效文件为基础增加字段，确保测试不会因其他格式错误而误通过。
		"unknown envelope field":   []byte(strings.TrimSuffix(string(file), "}") + `,"extra":true}`),
		"invalid payload base64":   []byte(`{"payload":"!","signature":"` + envelope.Signature + `"}`),
		"invalid signature base64": []byte(`{"payload":"` + envelope.Payload + `","signature":"!"}`),
		"empty payload":            []byte(`{"payload":"","signature":"` + envelope.Signature + `"}`),
		"short signature":          []byte(`{"payload":"YQ==","signature":"aA=="}`),
		"trailing value":           append(testSign(t, payload), []byte(` {}`)...),
		"trailing garbage":         append(testSign(t, payload), '!'),
		"unknown payload field":    testSignRaw(t, []byte(`{"expiresAt":null,"extra":true}`)),
		"missing expiry":           testSignRaw(t, []byte(`{"schemaVersion":1}`)),
		"invalid expiry":           testSignRaw(t, []byte(`{"expiresAt":"not a time"}`)),
		"payload trailing":         testSignRaw(t, []byte(`{"expiresAt":null} {}`)),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Verify(file, testKeys(), testOptions(payload)); !errors.Is(err, ErrMalformed) || !reflect.DeepEqual(got, Payload{}) {
				t.Fatalf("malformed file returned %+v, %v", got, err)
			}
		})
	}
}

// TestVerifyRejectsInvalidSignedPayload 验证即使签名正确，无效的授权字段仍被拒绝。
func TestVerifyRejectsInvalidSignedPayload(t *testing.T) {
	for name, change := range map[string]func(*Payload){
		"schema":               func(p *Payload) { p.SchemaVersion++ },
		"license id":           func(p *Payload) { p.LicenseID = " " },
		"customer":             func(p *Payload) { p.CustomerID = "" },
		"project":              func(p *Payload) { p.ProjectID = "" },
		"product":              func(p *Payload) { p.Product = "" },
		"algorithm":            func(p *Payload) { p.Machine.Algorithm = "other" },
		"digest":               func(p *Payload) { p.Machine.MachineCode = "v1:" + strings.Repeat("g", 64) },
		"zero issued":          func(p *Payload) { p.IssuedAt = time.Time{} },
		"non UTC issued":       func(p *Payload) { p.IssuedAt = testNow.In(time.FixedZone("UTC+8", 8*3600)) },
		"zero published":       func(p *Payload) { p.PublishedAt = &time.Time{} },
		"missing expiry":       func(p *Payload) { p.ExpiresAt = nil },
		"expiry before issued": func(p *Payload) { value := p.IssuedAt; p.ExpiresAt = &value },
		"perpetual expiry":     func(p *Payload) { p.Type = TypePerpetual },
		"unknown type":         func(p *Payload) { p.Type = "other" },
		"null limits":          func(p *Payload) { p.Limits = nil },
		"zero limit":           func(p *Payload) { p.Limits["robots"] = 0 },
		"blank limit":          func(p *Payload) { p.Limits[" "] = 1 },
		"null features":        func(p *Payload) { p.Features = nil },
		"blank feature":        func(p *Payload) { p.Features = []string{" "} },
		"duplicate feature":    func(p *Payload) { p.Features = []string{"transport", "transport"} },
	} {
		t.Run(name, func(t *testing.T) {
			payload := testPayload(t)
			options := testOptions(payload)
			change(&payload)
			wantErr := ErrInvalidPayload
			if name == "schema" {
				wantErr = ErrUnsupported
			}
			if got, err := Verify(testSign(t, payload), testKeys(), options); !errors.Is(err, wantErr) || !reflect.DeepEqual(got, Payload{}) {
				t.Fatalf("invalid signed payload returned %+v, %v; want no rights and %v", got, err, wantErr)
			}
		})
	}
}

// TestStatusJSONAndLongExpiry 验证跨 400 年的剩余天数计算和永久授权的 JSON 展示字段。
func TestStatusJSONAndLongExpiry(t *testing.T) {
	payload := testPayload(t)
	// 超过 time.Duration 可表示的约 290 年，仍准确计算天数。
	expires := testNow.AddDate(400, 0, 0)
	payload.ExpiresAt = &expires
	status, err := VerifyStatus(testSign(t, payload), testKeys(), testOptions(payload))
	if err != nil || status.RemainingDays != 146097 {
		t.Fatalf("long expiry = %+v, %v", status, err)
	}
	payload.Type, payload.ExpiresAt = TypePerpetual, nil
	status, err = VerifyStatus(testSign(t, payload), testKeys(), testOptions(payload))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["remainingDays"]) != "-1" || string(fields["expiresAt"]) != "null" || string(fields["state"]) != `"valid"` || string(fields["licenseId"]) != `"license-1"` {
		t.Fatalf("unexpected status JSON: %s", data)
	}
}
