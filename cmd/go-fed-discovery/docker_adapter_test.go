package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

)

const dockerLifecycleID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type cleanupDeadlineDockerRunner struct {
	runner          DockerCommandRunner
	cleanupDeadline chan<- time.Time
}

func (r cleanupDeadlineDockerRunner) Run(ctx context.Context, command DockerCommand) ([]byte, error) {
	if dockerLifecycleVerb(command.Args) != "rm" {
		return r.runner.Run(ctx, command)
	}

	deadline, _ := ctx.Deadline()
	r.cleanupDeadline <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}


func dockerLifecycleVerb(arguments []string) string {
	if len(arguments) < 5 {
		return ""
	}
	return arguments[4]
}

func lifecycleDockerRunner(t *testing.T) *fakeDockerCommandRunner {
	t.Helper()
	image := testDockerImage
	return &fakeDockerCommandRunner{run: func(command DockerCommand) ([]byte, error) {
		switch {
		case reflect.DeepEqual(command.Args, dockerVersionArgs):
			return []byte(`{"Client":{"Version":"24.0.0","ApiVersion":"1.43"},"Server":{"Version":"24.0.0","ApiVersion":"1.43"}}`), nil
		case reflect.DeepEqual(command.Args, dockerInfoArgs):
			return []byte(`{"ID":"daemon-id","ServerVersion":"24.0.0","OSType":"linux"}`), nil
		case reflect.DeepEqual(command.Args, dockerInspectArgs(image)):
			return []byte(`[{"Id":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","RepoDigests":["` + image + `"]}]`), nil
		case dockerLifecycleVerb(command.Args) == "create":
			return []byte(dockerLifecycleID + "\n"), nil
		case dockerLifecycleVerb(command.Args) == "container" && len(command.Args) > 5 && command.Args[5] == "inspect":
			return []byte(`[{"Id":"` + dockerLifecycleID + `","Config":{"Image":"` + image + `","User":"65532:65532","Cmd":["/usr/local/bin/tool","--emit","ok"]},"HostConfig":{"ReadonlyRootfs":true,"Memory":67108864,"NanoCpus":1500000000,"NetworkMode":"none","CapDrop":["ALL"]},"State":{"Running":false,"ExitCode":0}}]`), nil
		case dockerLifecycleVerb(command.Args) == "cp":
			if command.Stdin != nil {
				return nil, nil
			}
			return dockerResultTar([]byte("result"))
		case dockerLifecycleVerb(command.Args) == "start":
			return []byte("stdout"), nil
		case dockerLifecycleVerb(command.Args) == "rm":
			return nil, nil
		default:
			return nil, errors.New("unexpected docker lifecycle command")
		}
	}}
}

func TestDockerAdapterRunsStrictLifecycleAndRemovesLast(t *testing.T) {
	runner := lifecycleDockerRunner(t)
	adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
	if err != nil {
		t.Fatal(err)
	}
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := string(result.Result), "result"; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
	if result.MediaType != "application/octet-stream" || result.TranscriptMediaType != "application/json; charset=utf-8" {
		t.Fatalf("result media types = %q, %q", result.MediaType, result.TranscriptMediaType)
	}
	if len(runner.commands) < 2 || dockerLifecycleVerb(runner.commands[len(runner.commands)-1].Args) != "rm" {
		t.Fatalf("commands do not force-remove last: %#v", runner.commands)
	}
	if got := runner.commands[4]; dockerLifecycleVerb(got.Args) != "create" || !reflect.DeepEqual(got.Args[len(got.Args)-4:], append([]string{request.Image}, request.Command...)) {
		t.Fatalf("create command = %#v", got)
	}
}

func TestDockerAdapterUsesExpectedLifecycleArgvOrder(t *testing.T) {
	runner := lifecycleDockerRunner(t)
	adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
	if err != nil {
		t.Fatal(err)
	}
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Run(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(runner.commands))
	for index, command := range runner.commands {
		got[index] = dockerLifecycleVerb(command.Args)
		if got[index] == "image" || got[index] == "container" {
			got[index] += " " + command.Args[5]
		}
	}
	want := []string{"version", "info", "image inspect", "image inspect", "create", "container inspect", "cp", "start", "container inspect", "cp", "version", "info", "image inspect", "image inspect", "rm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lifecycle order = %#v; want %#v", got, want)
	}
	if !reflect.DeepEqual(runner.commands[4].Args, dockerCreateArgs(request)) {
		t.Fatalf("create argv = %#v; want %#v", runner.commands[4].Args, dockerCreateArgs(request))
	}
	if len(runner.commands[6].Stdin) == 0 || !reflect.DeepEqual(runner.commands[len(runner.commands)-1].Args, dockerRemoveArgs(dockerLifecycleID)) {
		t.Fatalf("copy/remove commands = %#v, %#v", runner.commands[6], runner.commands[len(runner.commands)-1])
	}
}


func TestDockerAdapterRejectsInvalidNormalizedLimitsBeforeRunner(t *testing.T) {
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DockerRunRequest)
	}{
		{name: "zero memory", mutate: func(r *DockerRunRequest) { r.MemoryBytes = 0 }},
		{name: "memory cap", mutate: func(r *DockerRunRequest) { r.MemoryBytes = dockerMaxMemoryBytes + 1 }},
		{name: "zero timeout", mutate: func(r *DockerRunRequest) { r.TimeoutMillis = 0 }},
		{name: "timeout cap", mutate: func(r *DockerRunRequest) { r.TimeoutMillis = dockerMaxTimeoutMillis + 1 }},
		{name: "zero output", mutate: func(r *DockerRunRequest) { r.MaxOutputBytes = 0 }},
		{name: "output cap", mutate: func(r *DockerRunRequest) { r.MaxOutputBytes = dockerMaxOutputBytes + 1 }},
		{name: "invalid cpu", mutate: func(r *DockerRunRequest) { r.CPUs = "65" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := lifecycleDockerRunner(t)
			adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
			if err != nil {
				t.Fatal(err)
			}
			candidate := request
			tt.mutate(&candidate)
			if _, err := adapter.Run(context.Background(), candidate); err == nil {
				t.Fatal("Run() succeeded; want limit error")
			}
			if len(runner.commands) != 0 {
				t.Fatalf("runner invoked for invalid limits: %#v", runner.commands)
			}
		})
	}
}
func TestDockerAdapterRemovesContainerAfterFailure(t *testing.T) {
	runner := lifecycleDockerRunner(t)
	original := runner.run
	runner.run = func(command DockerCommand) ([]byte, error) {
		if dockerLifecycleVerb(command.Args) == "start" {
			return nil, errors.New("start failed")
		}
		return original(command)
	}
	adapter, err := NewDockerCLIAdapter(runner, validDockerPreflightHost())
	if err != nil {
		t.Fatal(err)
	}
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Run(context.Background(), request); err == nil {
		t.Fatal("Run() succeeded; want start error")
	}
	if got := dockerLifecycleVerb(runner.commands[len(runner.commands)-1].Args); got != "rm" {
		t.Fatalf("last command = %q, want rm", got)
	}
}

func TestDockerAdapterBoundsIndependentCleanupAfterFailure(t *testing.T) {
	lifecycleRunner := lifecycleDockerRunner(t)
	startErr := errors.New("start failed")
	parentContext, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	original := lifecycleRunner.run
	lifecycleRunner.run = func(command DockerCommand) ([]byte, error) {
		if dockerLifecycleVerb(command.Args) == "start" {
			cancelParent()
			return nil, startErr
		}
		return original(command)
	}

	cleanupDeadline := make(chan time.Time, 1)
	adapter, err := NewDockerCLIAdapter(cleanupDeadlineDockerRunner{
		runner:          lifecycleRunner,
		cleanupDeadline: cleanupDeadline,
	}, validDockerPreflightHost())
	if err != nil {
		t.Fatal(err)
	}
	request, err := validateDockerWorkerProfile(validDockerWorkerProfile())
	if err != nil {
		t.Fatal(err)
	}

	type runOutcome struct {
		result DockerRunResult
		err    error
	}
	done := make(chan runOutcome, 1)
	go func() {
		result, runErr := adapter.Run(parentContext, request)
		done <- runOutcome{result: result, err: runErr}
	}()

	select {
	case deadline := <-cleanupDeadline:
		if deadline.IsZero() {
			t.Fatal("cleanup context has no deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup command did not start")
	}

	select {
	case outcome := <-done:
		t.Fatalf("Run() returned before cleanup deadline: result = %#v, error = %v", outcome.result, outcome.err)
	case <-time.After(dockerCleanupTimeout - time.Second):
	}

	select {
	case outcome := <-done:
		if !errors.Is(outcome.err, startErr) {
			t.Fatalf("Run() error = %v; want wrapped %v", outcome.err, startErr)
		}
		if outcome.result.Result != nil || outcome.result.MediaType != "" || outcome.result.Transcript != nil || outcome.result.TranscriptMediaType != "" || outcome.result.Evidence != nil {
			t.Fatalf("Run() result = %#v; want no result", outcome.result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cleanup deadline")
	}
}
