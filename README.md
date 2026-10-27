# LicenseX SDK for Go

[![English](https://img.shields.io/badge/English-selected-1677ff?style=for-the-badge)](README.md)
[![简体中文](https://img.shields.io/badge/简体中文-切换语言-555555?style=for-the-badge)](README-CN.md)

## About

LicenseX SDK for Go provides machine-bound, offline license management for Go applications. It generates license requests, verifies Ed25519 signatures, stores licenses locally, and checks license validity at business entry points.

- Bind licenses to a product and a device using a machine code derived from the product ID and device UUID.
- Support trial, perpetual, and time-limited licenses.
- Import and persist signed licenses, with status, remaining days, features, and usage limits available to your application.
- Verify licenses locally without connecting to the LicenseX issuer. Request delivery, approval, and license delivery are handled outside the SDK.

## Requirements

- Go **1.27.0 or later**, as specified in [go.mod](go.mod).
- Automatic device UUID collection supports Linux (DMI UUID) and macOS (IOPlatformUUID).
- For containers, other systems, or deployments where automatic collection is unavailable, supply a stable, trusted deployment device UUID through `ManagerOptions.DeviceUUID`. Collection failures return an error; the SDK does not generate a random fallback identity.

## Installation

```sh
go get github.com/go-ashe/licensex-sdk-go
```

Import the SDK using the package name `licensex`:

```go
import "github.com/go-ashe/licensex-sdk-go"
```

## Quick start

Obtain the **product ID**, **key ID**, and **public key Base64** from LicenseX product management. The public key must be the standard Base64 encoding of a raw, 32-byte Ed25519 public key; PEM and X.509 keys are not accepted.

The integration flow is: **initialize → load → export request → import license → check business access**. Create one long-lived `Manager` for each product and device combination.

### Initialize and load a license

This example reads trusted configuration from environment variables. Set `LICENSEX_PRODUCT_ID`, `LICENSEX_KEY_ID`, and `LICENSEX_PUBLIC_KEY_BASE64` before running it. `LICENSEX_DEVICE_UUID` is optional; leave it empty to collect the local device UUID automatically.

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
		log.Printf("Load license: %v", err)
	}
	log.Printf("Machine code: %s", manager.MachineCode())
	if _, err := manager.Check(); err != nil {
		log.Printf("Licensed operations unavailable: %v", err)
		return
	}
	log.Print("License is valid")
}
```

`NewManager()` does not read the saved license; call `Load()` explicitly at startup. A missing license is expected on first use. A running service can keep its request and import endpoints available while `Check()` blocks licensed operations.

### Export a license request

The following snippets use the initialized `manager` above and run inside your application functions. Generate requests on the final deployment device:

```go
request, err := manager.Request("1.0.0")
if err != nil {
	return err
}
if err := licensex.WriteRequest("request.json", request); err != nil {
	return err
}
```

Submit `request.json` to LicenseX for approval and signing. The version argument is your application's version. Requests contain the product ID, version, and machine code, without the raw device UUID. Requests are unsigned; eligibility is determined by LicenseX approval. Requests can be generated before activation or after expiration.

`WriteRequest()` requires an existing parent directory and refuses to overwrite an existing file. For an HTTP download, use `licensex.MarshalRequest(request)` to obtain the JSON bytes.

### Import a signed license

Pass the complete, original license file to `Import()`:

```go
data, err := os.ReadFile("issued-license.lic")
if err != nil {
	return err
}
status, err := manager.Import(data)
if err != nil {
	return err
}
log.Printf("License %s imported; state: %s", status.LicenseID, status.State)
```

Import verifies the signature, fields, product, device, and validity period, then saves the license before publishing it in memory. Renew a license by importing a newly issued file; it replaces the previous license, including its features and limits.

For HTTP uploads, bound the read with `io.ReadAll(io.LimitReader(reader, licensex.MaxLicenseSize+1))` and reject data exceeding `MaxLicenseSize`. Pass the original envelope containing `payload` and `signature` to `Import()`.

### Check business access

Call `Check()` at every licensed business entry point, then enforce the granted features and limits in your application. For example:

```go
package integration

import (
	"fmt"
	"slices"

	"github.com/go-ashe/licensex-sdk-go"
)

func CheckTransport(manager *licensex.Manager, totalRobots int) error {
	if totalRobots < 0 {
		return fmt.Errorf("robot count must not be negative")
	}
	payload, err := manager.Check()
	if err != nil {
		return err
	}
	if !slices.Contains(payload.Features, "transport") {
		return fmt.Errorf("transport feature is not licensed")
	}
	limit, ok := payload.Limits["robots"]
	if !ok || limit <= 0 || totalRobots > limit {
		return fmt.Errorf("robot count exceeds the licensed limit")
	}
	return nil
}
```

Here, `totalRobots` is the total count after the proposed operation. Unlisted features and limits are not granted. The SDK does not track or reserve usage; coordinate the limit check and business write in a transaction or other concurrency control.

### Query license status

```go
status, err := manager.Status()
if err != nil && !errors.Is(err, licensex.ErrNotActivated) {
	return err
}
log.Printf("State: %s; remaining days: %d", status.State, status.RemainingDays)
```

`Status()` recalculates the state on every call and returns trusted details even for expired or not-yet-valid licenses. Before activation, it returns `LicenseStateNotActivated` together with `ErrNotActivated`; the other fields have zero values. Use `Check()` for business access decisions.

| State | JSON value | Meaning |
| --- | --- | --- |
| `LicenseStateNotActivated` | `not_activated` | No trusted license has been loaded or imported |
| `LicenseStateNotYetValid` | `not_yet_valid` | The license has not reached its start time |
| `LicenseStateValid` | `valid` | The license is active and has not expired |
| `LicenseStateExpired` | `expired` | The expiration time has been reached |

`RemainingDays` rounds partial days up, returns `-1` for perpetual licenses, and `0` for expired licenses. The validity interval is `[issuedAt, expiresAt)`; perpetual licenses still have a start time. `status.State.ShowText()` returns a Chinese display label; use the state values to provide other translations.

## Configuration

| `ManagerOptions` field | Description |
| --- | --- |
| `ProductID` | Required. Must match the issuer's product ID; case-sensitive after trimming surrounding whitespace. |
| `PubKeys` | Required. At least one trusted key, indexed by the issuer's key ID. Use `ParsePublicKeys()` to parse Base64 configuration. |
| `Storage` | Required. Use `NewFileStorage(path)` or implement the `Storage` interface. |
| `DeviceUUID` | Optional. Leave empty for automatic collection, or supply a stable UUID in `8-4-4-4-12` hexadecimal format. All-zero and all-`f` UUIDs are rejected. |
| `Now` | Optional. Defaults to `time.Now`. A custom clock must be trusted, safe for concurrent calls, and return a nonzero time. |

## Error handling

Use `errors.Is()` to inspect errors, including wrapped filesystem errors.

| Error | Suggested action |
| --- | --- |
| `ErrNotActivated`, `os.ErrNotExist` | Offer request export and license import. `Load()` returns `os.ErrNotExist` when no file exists. |
| `ErrExpired`, `ErrNotYetValid` | Deny licensed operations and display the validity period. |
| `ErrWrongProduct`, `ErrWrongMachine` | Check the product ID and deployment device. |
| `ErrUnknownKey`, `ErrBadSignature` | Check the trusted keys and the original signed file. |
| `ErrMalformed`, `ErrUnsupported`, `ErrInvalidPayload` | Check the file format, schema version, and license fields. |
| `ErrInvalidOptions`, `ErrInvalidRequest`, `ErrInvalidVerifyOptions` | Check configuration and API arguments. |

Device identity collection and storage can also return underlying errors. Handle every non-nil error.

## Notes

- **Loading and importing:** `Load()` accepts authentic licenses that are expired or not yet valid so their details can be displayed. A read or verification failure clears the in-memory license. `Import()` rejects expired or not-yet-valid licenses and preserves the previous license on validation or save failure.
- **Storage:** Request JSON and license files each have a 1 MiB limit. Create parent directories before use. `FileStorage` atomically replaces the license using a temporary file with `0600` permissions. Custom `Storage.Save()` implementations must preserve the old data on failure.
- **Concurrency:** A `Manager` supports concurrent use, and returned values are isolated from its internal state. It does not watch for file changes; coordinate updates across processes and call `Load()` explicitly when needed.
- **Key rotation:** Configure both old and new trusted keys during a transition. Recreate the manager or restart the service after a key configuration change, then load the license again.
- **Offline operation:** The SDK does not provide revocation, protection against restoring an older license, or clock rollback detection across restarts. Issuing a replacement does not automatically invalidate old copies.
- **Direct verification:** Use `Verify()` when managing license state yourself, or `VerifyStatus()` to also display expired or not-yet-valid licenses. `ParsePayload()` and `ValidatePayload()` do not verify signatures and cannot establish business access on their own.

## Documentation and support

- [Types and options](types.go), [constants and states](cons.go), [errors](errors.go)
- [Report an issue](https://github.com/go-ashe/licensex-sdk-go/issues)

## License

This project is licensed under the [MIT License](LICENSE).
