package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

const (
	dockerPreflightImage       = "registry.example/agent/tool@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	dockerPreflightImageDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type fakeDockerCommandRunner struct {
	commands []DockerCommand
	run      func(DockerCommand) ([]byte, error)
}

func (r *fakeDockerCommandRunner) Run(_ context.Context, command DockerCommand) ([]byte, error) {
	r.commands = append(r.commands, command)
	return r.run(command)
}

func validDockerPreflightHost() DockerHost {
	return DockerHost{
		CommandPath: dockerCommandPath,
		SocketPath:  dockerLocalUnixSocket,
		Environment: []string{"PATH=/untrusted/bin", "HOME=/untrusted/home"},
		BinaryDigest: func(string) (string, error) {
			return "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", nil
		},
		SocketIdentity: func(string) (DockerSocketIdentity, error) {
			return DockerSocketIdentity{Device: 1, Inode: 2, Mode: 0o140660, UID: 0}, nil
		},
	}
}

func validDockerPreflightRunner() *fakeDockerCommandRunner {
	return &fakeDockerCommandRunner{run: func(command DockerCommand) ([]byte, error) {
		switch {
		case reflect.DeepEqual(command.Args, dockerVersionArgs):
			return []byte(`{"Client":{"Version":"24.0.0","ApiVersion":"1.43"},"Server":{"Version":"24.0.0","ApiVersion":"1.43"}}`), nil
		case reflect.DeepEqual(command.Args, dockerInfoArgs):
			return []byte(`{"ID":"daemon-id","ServerVersion":"24.0.0","OSType":"linux"}`), nil
		case len(command.Args) == len(dockerInspectArgs(dockerPreflightImage)) && reflect.DeepEqual(command.Args, dockerInspectArgs(dockerPreflightImage)):
			return []byte(`[{"Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","RepoDigests":["` + dockerPreflightImage + `"],"Descriptor":{"Digest":"` + dockerPreflightImageDigest + `"}}]`), nil
		default:
			return nil, errors.New("unexpected docker command")
		}
	}}
}

func TestDockerPreflightAcceptsExactLocalIdentity(t *testing.T) {
	runner := validDockerPreflightRunner()
	adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
	if err != nil {
		t.Fatalf("NewDockerCLIAdapter() error = %v", err)
	}

	probe, err := adapter.Preflight(context.Background(), dockerPreflightImage)
	if err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	if probe.Image != dockerPreflightImage || probe.ImageDescriptorDigest != dockerPreflightImageDigest || probe.ImageID != "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("probe image identity = %+v", probe)
	}
	if probe.BinaryDigest != "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" || probe.DaemonID != "daemon-id" {
		t.Errorf("probe host identity = %+v", probe)
	}

	wantCommands := []DockerCommand{
		{Path: dockerCommandPath, Args: dockerVersionArgs, Env: dockerSanitizedEnvironment},
		{Path: dockerCommandPath, Args: dockerInfoArgs, Env: dockerSanitizedEnvironment},
		{Path: dockerCommandPath, Args: dockerInspectArgs(dockerPreflightImage), Env: dockerSanitizedEnvironment},
		{Path: dockerCommandPath, Args: dockerInspectArgs(dockerPreflightImage), Env: dockerSanitizedEnvironment},
	}
	if !reflect.DeepEqual(runner.commands, wantCommands) {
		t.Errorf("docker commands = %#v; want %#v", runner.commands, wantCommands)
	}
}

func TestDockerPreflightRejectsUnsafeHostConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DockerHost)
	}{
		{name: "non-fixed command", mutate: func(host *DockerHost) { host.CommandPath = "/opt/docker" }},
		{name: "non-local endpoint", mutate: func(host *DockerHost) { host.SocketPath = "/tmp/docker.sock" }},
		{name: "remote host", mutate: func(host *DockerHost) { host.Environment = append(host.Environment, "DOCKER_HOST=tcp://remote:2376") }},
		{name: "non-default context", mutate: func(host *DockerHost) { host.Environment = append(host.Environment, "DOCKER_CONTEXT=remote") }},
		{name: "inherited config", mutate: func(host *DockerHost) { host.Environment = append(host.Environment, "DOCKER_CONFIG=/tmp/docker") }},
		{name: "TLS override", mutate: func(host *DockerHost) { host.Environment = append(host.Environment, "DOCKER_TLS_VERIFY=1") }},
		{name: "API override", mutate: func(host *DockerHost) { host.Environment = append(host.Environment, "DOCKER_API_VERSION=1.99") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := validDockerPreflightHost()
			tt.mutate(&host)
			if _, err := NewDockerCLIAdapter(validDockerPreflightRunner(), host); err == nil {
				t.Fatal("NewDockerCLIAdapter() succeeded; want error")
			}
		})
	}
}

func TestDockerPreflightRejectsIdentityAndStructuredOutputFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DockerHost, *fakeDockerCommandRunner)
	}{
		{name: "binary changed", mutate: func(host *DockerHost, _ *fakeDockerCommandRunner) {
			calls := 0
			host.BinaryDigest = func(string) (string, error) {
				calls++
				if calls == 1 {
					return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
				}
				return "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
			}
		}},
		{name: "invalid binary digest", mutate: func(host *DockerHost, _ *fakeDockerCommandRunner) {
			host.BinaryDigest = func(string) (string, error) { return "not-a-digest", nil }
		}},
		{name: "unsafe socket identity", mutate: func(host *DockerHost, _ *fakeDockerCommandRunner) {
			host.SocketIdentity = func(string) (DockerSocketIdentity, error) {
				return DockerSocketIdentity{Device: 1, Inode: 2, Mode: 0o100600, UID: 0}, nil
			}
		}},
		{name: "socket changed", mutate: func(host *DockerHost, _ *fakeDockerCommandRunner) {
			calls := 0
			host.SocketIdentity = func(string) (DockerSocketIdentity, error) {
				calls++
				return DockerSocketIdentity{Device: 1, Inode: uint64(calls), Mode: 0o140660, UID: 0}, nil
			}
		}},
		{name: "old client", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerVersionArgs) {
					return []byte(`{"Client":{"Version":"23.0.0","ApiVersion":"1.43"},"Server":{"Version":"24.0.0","ApiVersion":"1.43"}}`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "old API", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerVersionArgs) {
					return []byte(`{"Client":{"Version":"24.0.0","ApiVersion":"1.42"},"Server":{"Version":"24.0.0","ApiVersion":"1.43"}}`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "missing daemon identity", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerInfoArgs) {
					return []byte(`{"ServerVersion":"24.0.0","OSType":"linux"}`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "non linux daemon", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerInfoArgs) {
					return []byte(`{"ID":"daemon-id","ServerVersion":"24.0.0","OSType":"windows"}`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "malformed JSON", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerVersionArgs) {
					return []byte("not-json"), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "repo digest mismatch", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerInspectArgs(dockerPreflightImage)) {
					return []byte(`[{"Id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","RepoDigests":["registry.example/agent/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"Descriptor":{"Digest":"` + dockerPreflightImageDigest + `"}}]`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "invalid image ID", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerInspectArgs(dockerPreflightImage)) {
					return []byte(`[{"Id":"not-a-digest","RepoDigests":["` + dockerPreflightImage + `"],"Descriptor":{"Digest":"` + dockerPreflightImageDigest + `"}}]`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
		{name: "image changed", mutate: func(_ *DockerHost, runner *fakeDockerCommandRunner) {
			calls := 0
			runner.run = func(command DockerCommand) ([]byte, error) {
				if reflect.DeepEqual(command.Args, dockerInspectArgs(dockerPreflightImage)) {
					calls++
					id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
					if calls == 2 {
						id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					}
					return []byte(`[{"Id":"sha256:` + id + `","RepoDigests":["` + dockerPreflightImage + `"],"Descriptor":{"Digest":"` + dockerPreflightImageDigest + `"}}]`), nil
				}
				return validDockerPreflightRunner().run(command)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := validDockerPreflightHost()
			runner := validDockerPreflightRunner()
			tt.mutate(&host, runner)
			adapter, err := NewDockerCLIAdapter(runner, host)
			if err != nil {
				t.Fatalf("NewDockerCLIAdapter() error = %v", err)
			}
			if _, err := adapter.Preflight(context.Background(), dockerPreflightImage); err == nil {
				t.Fatal("Preflight() succeeded; want error")
			}
		})
	}
}

func TestDockerPreflightRejectsTagOnlyImageBeforeRunner(t *testing.T) {
	runner := validDockerPreflightRunner()
	adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Preflight(context.Background(), "registry.example/agent/tool:latest"); err == nil {
		t.Fatal("Preflight() succeeded for tag-only image; want error")
	}
	if len(runner.commands) != 0 {
		t.Errorf("runner calls = %#v; want none", runner.commands)
	}
}
