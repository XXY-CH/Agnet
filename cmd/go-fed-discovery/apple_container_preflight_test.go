package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const applePreflightTestImage = "docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"
const applePreflightLookupImage = "docker.io/library/node:24-alpine"

type appleContainerRunnerFunc func(context.Context, string, ...string) ([]byte, error)

func (fn appleContainerRunnerFunc) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return fn(ctx, executable, arguments...)
}

func cleanApplePreflightEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CONTAINER_HOST", "CONTAINER_CONFIG", "CONTAINER_SSH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"} {
		t.Setenv(name, "")
	}
	t.Setenv("AGNET_CONTAINER_RUNTIME", "apple-container")
}

func TestAppleContainerPreflightAcceptsFixedLocalPinnedImage(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	runner, calls := validAppleContainerRunner(t, applePreflightTestImage)
	adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
	adapter.readFile = func(path string) ([]byte, error) {
		if path != appleContainerBinaryPath {
			t.Fatalf("binary path = %q", path)
		}
		return []byte("signed-apple-container"), nil
	}

	proof, err := adapter.Preflight(context.Background(), applePreflightTestImage)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Runtime != "apple-container" || proof.BinaryPath != appleContainerBinaryPath {
		t.Fatalf("runtime proof = %#v", proof)
	}
	if proof.ImageDescriptorDigest != "sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd" || proof.ImageID != "a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd" {
		t.Fatalf("image proof = %#v", proof)
	}
	if proof.APIServerVersion != "1.1.0" || proof.APIServerCommit != appleAPIServerFullCommit || proof.AppRoot != "/Users/alice/Library/Application Support/com.apple.container" {
		t.Fatalf("server proof = %#v", proof)
	}
	if proof.BinaryDigestBefore != proof.BinaryDigestAfter || proof.CLIVersionBefore != proof.CLIVersionAfter || proof.APIServerVersionBefore != proof.APIServerVersionAfter || proof.APIServerCommitBefore != proof.APIServerCommitAfter {
		t.Fatalf("preflight did not retain stable identities: %#v", proof)
	}
	for _, call := range *calls {
		if strings.Contains(call, "pull") || strings.Contains(call, "run") || strings.Contains(call, "build") {
			t.Fatalf("preflight made a non-read-only call: %q", call)
		}
	}
	inspectCalls := 0
	for _, call := range *calls {
		if call == appleContainerBinaryPath+" image inspect "+applePreflightLookupImage {
			inspectCalls++
		}
	}
	if inspectCalls != 2 {
		t.Fatalf("local tagged image inspections = %d; want 2; calls = %#v", inspectCalls, *calls)
	}
}
func TestAppleContainerSystemStatusRequiresFullCommitWithVersionPrefix(t *testing.T) {
	tests := []struct {
		name    string
		status  []byte
		wantErr string
	}{
		{
			name:    "mismatched full commit",
			status:  appleStatusWithAPIServerCommit("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
			wantErr: "version or commit is malformed",
		},
		{
			name:    "malformed full commit",
			status:  appleStatusWithAPIServerCommit("5973b9cc626a3e7a499bb316a958237ebe14e2eg"),
			wantErr: "version or commit is malformed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := newAppleContainerCLIAdapter(appleContainerRunnerFunc(func(_ context.Context, executable string, args ...string) ([]byte, error) {
				if executable != appleContainerBinaryPath || strings.Join(args, " ") != "system status --format json" {
					return nil, fmt.Errorf("unexpected command %q %q", executable, args)
				}
				return test.status, nil
			}), "/Users/alice")

			_, err := adapter.systemStatus(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("systemStatus() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestAppleContainerPreflightSmoke(t *testing.T) {
	image := os.Getenv("AGNET_APPLE_CONTAINER_SMOKE_IMAGE")
	if image == "" {
		t.Skip("set AGNET_APPLE_CONTAINER_SMOKE_IMAGE to run the read-only Apple container smoke test")
	}
	cleanApplePreflightEnvironment(t)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	lookupImage, _, _ := strings.Cut(image, "@")
	runner := appleContainerRunnerFunc(func(ctx context.Context, executable string, args ...string) ([]byte, error) {
		command := strings.Join(args, " ")
		allowed := command == "--version" || command == "system status --format json" || (len(args) == 3 && args[0] == "image" && args[1] == "inspect" && args[2] == lookupImage)
		if !allowed {
			return nil, fmt.Errorf("unexpected non-read-only apple container command %q", command)
		}
		t.Logf("real read-only command: %s %s", executable, command)
		return exec.CommandContext(ctx, executable, args...).Output()
	})
	if _, err := AppleContainerPreflight(context.Background(), runner, homeDir, image); err != nil {
		t.Fatal(err)
	}
}

func TestAppleContainerPreflightRejectsUnsafeInputsAndMutations(t *testing.T) {
	cleanApplePreflightEnvironment(t)
	tests := []struct {
		name    string
		image   string
		mutate  func(*AppleContainerCLIAdapter, *int)
		unsafe  string
		wantErr string
	}{
		{name: "tag only", image: "docker.io/library/node:22", wantErr: "one digest pin"},
		{name: "uppercase digest", image: "docker.io/library/node@sha256:A0B9BF06E4E6193CF7A0F58816CC935FF8C2A908F81E6F1A95432D679C54FBFD", wantErr: "lowercase"},
		{name: "digest without tag", image: "docker.io/library/node@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd", wantErr: "apple container local lookup requires a tag before @"},
		{name: "malformed digest", image: "docker.io/library/node@sha256:abc", wantErr: "64"},
		{name: "remote environment", image: applePreflightTestImage, unsafe: "CONTAINER_HOST=tcp://remote.example:2375", wantErr: "unsafe environment"},
		{name: "configuration environment", image: applePreflightTestImage, unsafe: "CONTAINER_CONFIG=/tmp/container-config", wantErr: "unsafe environment"},
		{name: "binary mutation", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, reads *int) {
			adapter.readFile = func(string) ([]byte, error) {
				*reads++
				if *reads == 1 {
					return []byte("first"), nil
				}
				return []byte("second"), nil
			}
		}, wantErr: "binary changed"},
		{name: "CLI version mutation", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			calls := 0
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, executable string, args ...string) ([]byte, error) {
				if executable != appleContainerBinaryPath {
					return nil, fmt.Errorf("unexpected executable %q", executable)
				}
				if len(args) == 1 && args[0] == "--version" {
					calls++
					if calls == 2 {
						return []byte("container CLI version 1.1.1 (build: release, commit: 5973b9c)\n"), nil
					}
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				if strings.Join(args, " ") == "system status --format json" {
					return validAppleStatusJSON(), nil
				}
				if len(args) == 3 && args[0] == "image" && args[1] == "inspect" {
					return validAppleImageInspectJSON(applePreflightTestImage), nil
				}
				return nil, errors.New("unexpected call")
			})
		}, wantErr: "CLI version changed"},
		{name: "CLI commit mismatch", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "--version":
					return []byte("container CLI version 1.1.0 (build: release, commit: deadbee)\n"), nil
				case "system status --format json":
					return validAppleStatusJSON(), nil
				default:
					return nil, errors.New("unexpected call")
				}
			})
		}, wantErr: "CLI and API server version or commit do not match"},
		{name: "apiserver commit mutation", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			statusCalls := 0
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch strings.Join(args, " ") {
				case "--version":
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				case "system status --format json":
					statusCalls++
					if statusCalls == 2 {
						return []byte(strings.ReplaceAll(string(validAppleStatusJSON()), "5973b9c", "deadbee")), nil
					}
					return validAppleStatusJSON(), nil
				default:
					if len(args) == 3 && args[0] == "image" && args[1] == "inspect" {
						return validAppleImageInspectJSON(applePreflightTestImage), nil
					}
					return nil, errors.New("unexpected call")
				}
			})
		}, wantErr: "API server identity changed"},
		{name: "stopped API server", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				return []byte(`{"status":"not running"}`), nil
			})
		}, wantErr: "not running"},
		{name: "malformed API server status", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				return []byte(`{"status":`), nil
			})
		}, wantErr: "status is malformed"},
		{name: "unexpected app root", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				if strings.Join(args, " ") == "system status --format json" {
					return []byte(strings.Replace(string(validAppleStatusJSON()), "/Users/alice/Library/Application Support/com.apple.container", "/tmp/remote", 1)), nil
				}
				return validAppleImageInspectJSON(applePreflightTestImage), nil
			})
		}, wantErr: "appRoot"},
		{name: "local tag mismatch", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				if strings.Join(args, " ") == "system status --format json" {
					return validAppleStatusJSON(), nil
				}
				return []byte(strings.Replace(string(validAppleImageInspectJSON(applePreflightTestImage)), `"name":"docker.io/library/node:24-alpine"`, `"name":"docker.io/library/node:stable"`, 1)), nil
			})
		}, wantErr: "local tagged reference"},
		{name: "inspect mismatch", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				if strings.Join(args, " ") == "system status --format json" {
					return validAppleStatusJSON(), nil
				}
				return []byte(strings.Replace(string(validAppleImageInspectJSON(applePreflightTestImage)), `"digest":"sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"`, `"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, 1)), nil
			})
		}, wantErr: "descriptor digest"},
		{name: "image ID mismatch", image: applePreflightTestImage, mutate: func(adapter *AppleContainerCLIAdapter, _ *int) {
			adapter.runner = appleContainerRunnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if strings.Join(args, " ") == "--version" {
					return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
				}
				if strings.Join(args, " ") == "system status --format json" {
					return validAppleStatusJSON(), nil
				}
				return []byte(strings.Replace(string(validAppleImageInspectJSON(applePreflightTestImage)), `"id":"a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd"`, `"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, 1)), nil
			})
		}, wantErr: "image id"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.unsafe != "" {
				name, value, _ := strings.Cut(test.unsafe, "=")
				t.Setenv(name, value)
			} else {
				t.Setenv("CONTAINER_HOST", "")
				t.Setenv("CONTAINER_CONFIG", "")
			}
			runner, _ := validAppleContainerRunner(t, applePreflightTestImage)
			adapter := newAppleContainerCLIAdapter(runner, "/Users/alice")
			reads := 0
			adapter.readFile = func(path string) ([]byte, error) {
				if path != appleContainerBinaryPath {
					t.Fatalf("binary path = %q", path)
				}
				return []byte("signed-apple-container"), nil
			}
			if test.mutate != nil {
				test.mutate(adapter, &reads)
			}
			_, err := adapter.Preflight(context.Background(), test.image)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Preflight() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func validAppleContainerRunner(t *testing.T, image string) (appleContainerRunner, *[]string) {
	t.Helper()
	calls := new([]string)
	return appleContainerRunnerFunc(func(_ context.Context, executable string, args ...string) ([]byte, error) {
		*calls = append(*calls, executable+" "+strings.Join(args, " "))
		if executable != appleContainerBinaryPath {
			return nil, fmt.Errorf("unexpected executable %q", executable)
		}
		switch strings.Join(args, " ") {
		case "--version":
			return []byte("container CLI version 1.1.0 (build: release, commit: 5973b9c)\n"), nil
		case "system status --format json":
			return validAppleStatusJSON(), nil
		default:
			lookupImage, _, _ := strings.Cut(image, "@")
			if len(args) == 3 && args[0] == "image" && args[1] == "inspect" && args[2] == lookupImage {
				return validAppleImageInspectJSON(image), nil
			}
			return nil, fmt.Errorf("unexpected args %q", args)
		}
	}), calls
}

const appleAPIServerFullCommit = "5973b9cc626a3e7a499bb316a958237ebe14e2ed"

func validAppleStatusJSON() []byte {
	return []byte(`{"status":"running","appRoot":"/Users/alice/Library/Application Support/com.apple.container/","installRoot":"/usr/local","apiServerVersion":"container-apiserver version 1.1.0 (build: release, commit: 5973b9c)","apiServerCommit":"5973b9cc626a3e7a499bb316a958237ebe14e2ed","apiServerBuild":"release","apiServerAppName":"container-apiserver"}`)
}

func appleStatusWithAPIServerCommit(commit string) []byte {
	return []byte(strings.Replace(string(validAppleStatusJSON()), `"apiServerCommit":"`+appleAPIServerFullCommit, `"apiServerCommit":"`+commit, 1))
}

func validAppleImageInspectJSON(image string) []byte {
	lookupImage, digest, _ := strings.Cut(image, "@")
	return []byte(`[{"id":"` + strings.TrimPrefix(digest, "sha256:") + `","configuration":{"name":"` + lookupImage + `","descriptor":{"digest":"` + digest + `"}},"variants":[]}]`)
}
