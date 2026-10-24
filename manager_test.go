package licensex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testSaveStorage 记录是否尝试保存，并可模拟存储故障。
type testSaveStorage struct {
	Storage
	saveErr error
	called  bool
}

func (s *testSaveStorage) Save(data []byte) error {
	s.called = true
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.Storage.Save(data)
}

// testManager 使用固定设备 UUID、测试公钥和临时文件存储创建管理器。
// now 为 nil 时使用默认时间源，初始化失败则终止当前测试。
func testManager(t *testing.T, now func() time.Time) (*Manager, *FileStorage) {
	t.Helper()
	storage, err := NewFileStorage(filepath.Join(t.TempDir(), "license.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(ManagerOptions{
		ProductID: " RCS100 ", PubKeys: testKeys(), Storage: storage,
		DeviceUUID: testUUID, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager, storage
}

// TestManagerNotActivated 验证未激活状态可供展示，且业务检查仍拒绝访问。
func TestManagerNotActivated(t *testing.T) {
	manager, _ := testManager(t, nil)
	status, err := manager.Status()
	if !errors.Is(err, ErrNotActivated) || status.State != LicenseStateNotActivated {
		t.Fatalf("Status = %+v, %v; want not activated", status, err)
	}
	if status.State.ShowText() != "未激活" {
		t.Fatalf("ShowText = %q; want 未激活", status.State.ShowText())
	}
	if payload, err := manager.Check(); !errors.Is(err, ErrNotActivated) || !reflect.DeepEqual(payload, Payload{}) {
		t.Fatalf("Check = %+v, %v; want no usable license", payload, err)
	}
}

// TestManagerRequestVersion 验证初始化无需产品版本，生成申请时可传入不同版本并拒绝无效值。
func TestManagerRequestVersion(t *testing.T) {
	manager, _ := testManager(t, nil)
	for _, version := range []string{"1.0.0", "2.0.0"} {
		request, err := manager.Request(" " + version + "\n")
		if err != nil {
			t.Fatal(err)
		}
		if request.ProductID != "RCS100" || request.ProductVersion != version || request.Machine.MachineCode != manager.MachineCode() {
			t.Fatalf("unexpected request: %+v", request)
		}
		if _, err = MarshalRequest(request); err != nil {
			t.Fatalf("request cannot be exported: %v", err)
		}
	}
	for _, version := range []string{"", " \n", "1.\xff", strings.Repeat("a", MaxRequestSize+1)} {
		request, err := manager.Request(version)
		if !errors.Is(err, ErrInvalidRequest) || request != (Request{}) {
			t.Fatalf("invalid version returned %+v, %v", request, err)
		}
	}
}

// TestManagerLoadResultIsolation 验证加载后的状态正确，修改返回值不影响内部授权。
func TestManagerLoadResultIsolation(t *testing.T) {
	manager, storage := testManager(t, func() time.Time { return testNow })
	payload := testPayload(t)
	payload.Features = []string{"reports"}
	if err := storage.Save(testSign(t, payload)); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Load()
	if err != nil {
		t.Fatal(err)
	}
	if status.State != LicenseStateValid || status.RemainingDays != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	status.Limits["robots"]++
	status.Features[0] = "changed"
	*status.ExpiresAt = testNow.Add(-time.Hour)
	*status.PublishedAt = testNow
	got, err := manager.Check()
	if err != nil || !reflect.DeepEqual(got, payload) {
		t.Fatalf("load result changed internal license: %+v, %v", got, err)
	}
}

// TestManagerCurrentTime 验证 Status 和 Check 随时间变化更新结果，并拒绝零时间。
func TestManagerCurrentTime(t *testing.T) {
	now := testNow
	manager, _ := testManager(t, func() time.Time { return now })
	payload := testPayload(t)
	if _, err := manager.Import(testSign(t, payload)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		now   time.Time
		state LicenseState
		err   error
	}{
		{"valid", testNow, LicenseStateValid, nil},
		{"not yet valid", payload.IssuedAt.Add(-time.Second), LicenseStateNotYetValid, ErrNotYetValid},
		{"expired", *payload.ExpiresAt, LicenseStateExpired, ErrExpired},
		{"zero time", time.Time{}, "", ErrInvalidOptions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now = tc.now
			status, err := manager.Status()
			if tc.state == "" {
				if !errors.Is(err, tc.err) {
					t.Fatalf("status error = %v; want %v", err, tc.err)
				}
			} else if err != nil || status.State != tc.state {
				t.Fatalf("status = %+v, %v; want %s", status, err, tc.state)
			}
			if _, err := manager.Check(); !errors.Is(err, tc.err) {
				t.Fatalf("check error = %v; want %v", err, tc.err)
			}
		})
	}
}

// TestManagerLoadStates 验证加载失败清除旧授权，时间状态异常的可信授权仍可加载展示。
func TestManagerLoadStates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		change    func(*Payload)
		missing   bool
		malformed bool
		wantErr   error
		state     LicenseState
		checkErr  error
	}{
		{name: "missing", missing: true, wantErr: os.ErrNotExist},
		{name: "malformed", malformed: true, wantErr: ErrMalformed},
		{name: "wrong product", change: func(p *Payload) { p.Product = "other" }, wantErr: ErrWrongProduct},
		{name: "wrong machine", change: func(p *Payload) { p.Machine.MachineCode = "v1:" + strings.Repeat("a", 64) }, wantErr: ErrWrongMachine},
		{name: "unknown key", change: func(p *Payload) { p.KeyID = "other-key" }, wantErr: ErrUnknownKey},
		{name: "expired", change: func(p *Payload) { value := testNow; p.ExpiresAt = &value }, state: LicenseStateExpired, checkErr: ErrExpired},
		{name: "not yet valid", change: func(p *Payload) { p.IssuedAt = testNow.Add(time.Hour) }, state: LicenseStateNotYetValid, checkErr: ErrNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, storage := testManager(t, func() time.Time { return testNow })
			payload := testPayload(t)
			if _, err := manager.Import(testSign(t, payload)); err != nil {
				t.Fatal(err)
			}
			if tc.missing {
				if err := os.Remove(storage.path); err != nil {
					t.Fatal(err)
				}
			} else {
				if tc.change != nil {
					tc.change(&payload)
				}
				data := testSign(t, payload)
				if tc.malformed {
					data = []byte("invalid")
				}
				if err := storage.Save(data); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := manager.Load()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Load error = %v; want %v", err, tc.wantErr)
			}
			status, statusErr := manager.Status()
			if tc.wantErr != nil {
				if !reflect.DeepEqual(loaded, Status{}) || !errors.Is(statusErr, ErrNotActivated) || status.State != LicenseStateNotActivated || !reflect.DeepEqual(status.Payload, Payload{}) {
					t.Fatalf("failed load retained authorization: loaded=%+v, status=%+v, error=%v", loaded, status, statusErr)
				}
				if _, err := manager.Check(); !errors.Is(err, ErrNotActivated) {
					t.Fatalf("Check after failed load = %v", err)
				}
				return
			}
			if statusErr != nil || loaded.State != tc.state || status.State != tc.state || !reflect.DeepEqual(status.Payload, payload) {
				t.Fatalf("loaded time state = %+v, %v; want %s", status, statusErr, tc.state)
			}
			if _, err := manager.Check(); !errors.Is(err, tc.checkErr) {
				t.Fatalf("Check = %v; want %v", err, tc.checkErr)
			}
		})
	}
}

// TestManagerImportFailurePreservesLicense 验证拒绝新授权或保存失败时保留原文件及内存授权。
func TestManagerImportFailurePreservesLicense(t *testing.T) {
	saveErr := errors.New("storage unavailable")
	for _, tc := range []struct {
		name    string
		change  func(*Payload)
		invalid bool
		saveErr error
		wantErr error
	}{
		{name: "malformed", invalid: true, wantErr: ErrMalformed},
		{name: "wrong product", change: func(p *Payload) { p.Product = "other" }, wantErr: ErrWrongProduct},
		{name: "wrong machine", change: func(p *Payload) { p.Machine.MachineCode = "v1:" + strings.Repeat("a", 64) }, wantErr: ErrWrongMachine},
		{name: "expired", change: func(p *Payload) { value := testNow; p.ExpiresAt = &value }, wantErr: ErrExpired},
		{name: "not yet valid", change: func(p *Payload) { p.IssuedAt = testNow.Add(time.Hour) }, wantErr: ErrNotYetValid},
		{name: "save failure", saveErr: saveErr, wantErr: saveErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, storage := testManager(t, func() time.Time { return testNow })
			old := testPayload(t)
			oldFile := testSign(t, old)
			if _, err := manager.Import(oldFile); err != nil {
				t.Fatal(err)
			}
			tracked := &testSaveStorage{Storage: storage, saveErr: tc.saveErr}
			manager.storage = tracked
			candidate := testPayload(t)
			candidate.LicenseID = "replacement"
			if tc.change != nil {
				tc.change(&candidate)
			}
			data := testSign(t, candidate)
			if tc.invalid {
				data = nil
			}
			status, err := manager.Import(data)
			if !errors.Is(err, tc.wantErr) || !reflect.DeepEqual(status, Status{}) {
				t.Fatalf("Import = %+v, %v; want %v", status, err, tc.wantErr)
			}
			if tracked.called != (tc.saveErr != nil) {
				t.Fatalf("unexpected storage save attempt: %v", tracked.called)
			}
			if got, err := manager.Check(); err != nil || !reflect.DeepEqual(got, old) {
				t.Fatalf("failed import changed memory: %+v, %v", got, err)
			}
			if got, err := storage.Load(); err != nil || !bytes.Equal(got, oldFile) {
				t.Fatalf("failed import changed file: %q, %v", got, err)
			}
		})
	}
}

// TestManagerConcurrentAccess 在并发加载、导入和读取时检查授权一致性及返回值隔离。
func TestManagerConcurrentAccess(t *testing.T) {
	manager, _ := testManager(t, func() time.Time { return testNow })
	want := testPayload(t)
	file := testSign(t, want)
	if _, err := manager.Import(file); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"load", "import", "status", "check"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			for range 10 {
				var got Payload
				var err error
				if operation == "check" {
					got, err = manager.Check()
				} else {
					var status Status
					switch operation {
					case "load":
						status, err = manager.Load()
					case "import":
						status, err = manager.Import(file)
					case "status":
						status, err = manager.Status()
					}
					if status.State != LicenseStateValid {
						t.Fatalf("unexpected state: %s, %v", status.State, err)
					}
					got = status.Payload
				}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("inconsistent authorization: %+v, %v", got, err)
				}
				got.Limits["robots"]++
				got.Features[0] = "changed"
				*got.ExpiresAt = testNow
				*got.PublishedAt = testNow
			}
		})
	}
}
