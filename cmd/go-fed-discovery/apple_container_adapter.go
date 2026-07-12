package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const appleContainerBinaryPath = "/usr/local/bin/container"

var (
	appleContainerVersionPattern = regexp.MustCompile(`^container CLI version ([0-9]+\.[0-9]+\.[0-9]+) \(build: ([a-z]+), commit: ([0-9a-f]{7,64})\)$`)
	appleAPIServerVersionPattern = regexp.MustCompile(`^container-apiserver version ([0-9]+\.[0-9]+\.[0-9]+) \(build: ([a-z]+), commit: ([0-9a-f]{7,64})\)$`)
	appleAPIServerCommitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// appleContainerRunner is the narrow, injectable process boundary for read-only
// Apple container CLI preflight calls.
type appleContainerRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

// AppleContainerPreflightEvidence records the stable local identities proven
// before the Apple container runtime may be selected for a test.
type AppleContainerPreflightEvidence struct {
	Runtime                string
	BinaryPath             string
	BinaryDigestBefore     string
	BinaryDigestAfter      string
	CLIVersionBefore       string
	CLIVersionAfter        string
	CLICommit              string
	APIServerVersion       string
	APIServerCommit        string
	APIServerVersionBefore string
	APIServerVersionAfter  string
	APIServerCommitBefore  string
	APIServerCommitAfter   string
	AppRoot                string
	Image                  string
	ImageDescriptorDigest  string
	ImageID                string
}

// AppleContainerCLIAdapter owns fixed-local Apple CLI preflight and constrained
// lifecycle execution. It has no remote endpoint, pull, build, or host fallback.
type AppleContainerCLIAdapter struct {
	runner          appleContainerRunner
	homeDir         string
	readFile        func(string) ([]byte, error)
	lifecycleRunner appleContainerLifecycleRunner
	newContainerID  func() (string, error)
}

func newAppleContainerCLIAdapter(runner appleContainerRunner, homeDir string) *AppleContainerCLIAdapter {
	return &AppleContainerCLIAdapter{
		runner:   runner,
		homeDir:  homeDir,
		readFile: os.ReadFile,
	}
}

// AppleContainerPreflight verifies one locally present, digest-pinned OCI image
// with the supplied runner. It is intentionally read-only.
func AppleContainerPreflight(ctx context.Context, runner appleContainerRunner, homeDir, image string) (AppleContainerPreflightEvidence, error) {
	return newAppleContainerCLIAdapter(runner, homeDir).Preflight(ctx, image)
}

func (a *AppleContainerCLIAdapter) Preflight(ctx context.Context, image string) (AppleContainerPreflightEvidence, error) {
	if a == nil || a.runner == nil {
		return AppleContainerPreflightEvidence{}, errors.New("apple container runner is not configured")
	}
	if err := validateAppleContainerEnvironment(); err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	if err := validateDockerImage(image); err != nil {
		return AppleContainerPreflightEvidence{}, fmt.Errorf("apple container image: %w", err)
	}
	lookupImage, ok := dockerTaggedImageReference(image)
	if !ok {
		return AppleContainerPreflightEvidence{}, errors.New("apple container local lookup requires a tag before @")
	}
	if a.homeDir == "" || !filepath.IsAbs(a.homeDir) {
		return AppleContainerPreflightEvidence{}, errors.New("apple container home directory must be absolute")
	}

	binaryBefore, err := a.binaryDigest()
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	cliBefore, err := a.cliIdentity(ctx)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	serverBefore, err := a.systemStatus(ctx)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	if err := validateAppleSystemIdentity(cliBefore, serverBefore, a.homeDir); err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	imageBefore, err := a.imageInspect(ctx, lookupImage, image)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	serverAfter, err := a.systemStatus(ctx)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	cliAfter, err := a.cliIdentity(ctx)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	binaryAfter, err := a.binaryDigest()
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	imageAfter, err := a.imageInspect(ctx, lookupImage, image)
	if err != nil {
		return AppleContainerPreflightEvidence{}, err
	}
	if imageBefore != imageAfter {
		return AppleContainerPreflightEvidence{}, errors.New("apple container image identity changed during preflight")
	}

	if binaryBefore != binaryAfter {
		return AppleContainerPreflightEvidence{}, errors.New("apple container binary changed during preflight")
	}
	if cliBefore != cliAfter {
		return AppleContainerPreflightEvidence{}, errors.New("apple container CLI version changed during preflight")
	}
	if serverBefore != serverAfter {
		return AppleContainerPreflightEvidence{}, errors.New("apple container API server identity changed during preflight")
	}
	if err := validateAppleSystemIdentity(cliAfter, serverAfter, a.homeDir); err != nil {
		return AppleContainerPreflightEvidence{}, err
	}

	return AppleContainerPreflightEvidence{
		Runtime:                "apple-container",
		BinaryPath:             appleContainerBinaryPath,
		BinaryDigestBefore:     binaryBefore,
		BinaryDigestAfter:      binaryAfter,
		CLIVersionBefore:       cliBefore.version,
		CLIVersionAfter:        cliAfter.version,
		CLICommit:              cliBefore.commit,
		APIServerVersion:       serverBefore.version,
		APIServerCommit:        serverBefore.commit,
		APIServerVersionBefore: serverBefore.version,
		APIServerVersionAfter:  serverAfter.version,
		APIServerCommitBefore:  serverBefore.commit,
		APIServerCommitAfter:   serverAfter.commit,
		AppRoot:                serverBefore.appRoot,
		Image:                  image,
		ImageDescriptorDigest:  imageBefore.descriptorDigest,
		ImageID:                imageBefore.id,
	}, nil
}

func validateAppleContainerEnvironment() error {
	for _, name := range []string{
		"CONTAINER_HOST",
		"CONTAINER_CONFIG",
		"CONTAINER_SSH",
		"DOCKER_HOST",
		"DOCKER_CONTEXT",
		"DOCKER_CONFIG",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("apple container preflight rejects unsafe environment %s", name)
		}
	}
	runtime := os.Getenv("AGNET_CONTAINER_RUNTIME")
	if runtime != "" && runtime != "apple-container" {
		return errors.New("apple container preflight rejects unsafe environment AGNET_CONTAINER_RUNTIME")
	}
	return nil
}

func (a *AppleContainerCLIAdapter) binaryDigest() (string, error) {
	readFile := a.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	data, err := readFile(appleContainerBinaryPath)
	if err != nil {
		return "", fmt.Errorf("read apple container binary: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

type appleCLIIdentity struct {
	version string
	commit  string
}

func (a *AppleContainerCLIAdapter) cliIdentity(ctx context.Context) (appleCLIIdentity, error) {
	output, err := a.runner.Run(ctx, appleContainerBinaryPath, "--version")
	if err != nil {
		return appleCLIIdentity{}, fmt.Errorf("apple container version: %w", err)
	}
	matches := appleContainerVersionPattern.FindStringSubmatch(strings.TrimSpace(string(output)))
	if matches == nil {
		return appleCLIIdentity{}, errors.New("apple container version output is malformed")
	}
	return appleCLIIdentity{version: matches[1], commit: matches[3]}, nil
}

type appleSystemStatus struct {
	Status           string `json:"status"`
	AppRoot          string `json:"appRoot"`
	InstallRoot      string `json:"installRoot"`
	LogRoot          *string `json:"logRoot"`
	APIServerVersion string `json:"apiServerVersion"`
	APIServerCommit  string `json:"apiServerCommit"`
	APIServerBuild   string `json:"apiServerBuild"`
	APIServerAppName string `json:"apiServerAppName"`
}

type appleAPIServerIdentity struct {
	version string
	commit  string
	appRoot string
}

func (a *AppleContainerCLIAdapter) systemStatus(ctx context.Context) (appleAPIServerIdentity, error) {
	output, err := a.runner.Run(ctx, appleContainerBinaryPath, "system", "status", "--format", "json")
	if err != nil {
		return appleAPIServerIdentity{}, fmt.Errorf("apple container system status: %w", err)
	}
	var status appleSystemStatus
	if err := decodeOneJSON(output, &status); err != nil {
		return appleAPIServerIdentity{}, fmt.Errorf("apple container system status is malformed: %w", err)
	}
	if status.Status != "running" {
		return appleAPIServerIdentity{}, errors.New("apple container API server is not running")
	}
	if status.APIServerAppName != "container-apiserver" {
		return appleAPIServerIdentity{}, errors.New("apple container API server identity is malformed")
	}
	matches := appleAPIServerVersionPattern.FindStringSubmatch(status.APIServerVersion)
	if matches == nil || !appleAPIServerCommitPattern.MatchString(status.APIServerCommit) || !strings.HasPrefix(status.APIServerCommit, matches[3]) {
		return appleAPIServerIdentity{}, errors.New("apple container API server version or commit is malformed")
	}
	return appleAPIServerIdentity{version: matches[1], commit: status.APIServerCommit, appRoot: filepath.Clean(status.AppRoot)}, nil
}

func validateAppleSystemIdentity(cli appleCLIIdentity, server appleAPIServerIdentity, homeDir string) error {
	if server.version != cli.version || !strings.HasPrefix(server.commit, cli.commit) {
		return errors.New("apple container CLI and API server version or commit do not match")
	}
	wantAppRoot := filepath.Join(homeDir, "Library", "Application Support", "com.apple.container")
	if server.appRoot != wantAppRoot {
		return fmt.Errorf("apple container appRoot = %q, want current-user local appRoot %q", server.appRoot, wantAppRoot)
	}
	return nil
}

type appleImageInspect struct {
	ID            string `json:"id"`
	Configuration struct {
		CreationDate string `json:"creationDate"`
		Name         string `json:"name"`
		Descriptor   struct {
			Digest string `json:"digest"`
		} `json:"descriptor"`
	} `json:"configuration"`
	Variants []json.RawMessage `json:"variants"`
}

type appleImageIdentity struct {
	id               string
	descriptorDigest string
}

func (a *AppleContainerCLIAdapter) imageInspect(ctx context.Context, lookupImage, image string) (appleImageIdentity, error) {
	output, err := a.runner.Run(ctx, appleContainerBinaryPath, "image", "inspect", lookupImage)
	if err != nil {
		return appleImageIdentity{}, fmt.Errorf("apple container image inspect: %w", err)
	}
	var inspected []appleImageInspect
	if err := json.Unmarshal(output, &inspected); err != nil {
		return appleImageIdentity{}, fmt.Errorf("apple container image inspect is malformed: %w", err)
	}
	if len(inspected) != 1 {
		return appleImageIdentity{}, errors.New("apple container image inspect did not return exactly one image")
	}
	_, digest, _ := strings.Cut(image, "@")
	wantID := strings.TrimPrefix(digest, "sha256:")
	item := inspected[0]
	if item.Configuration.Name != lookupImage {
		return appleImageIdentity{}, errors.New("apple container image inspect name does not match local tagged reference")
	}
	if item.Configuration.Descriptor.Digest != digest {
		return appleImageIdentity{}, errors.New("apple container image descriptor digest does not match requested image")
	}
	if item.ID != wantID {
		return appleImageIdentity{}, errors.New("apple container image id does not match requested image")
	}
	return appleImageIdentity{id: item.ID, descriptorDigest: item.Configuration.Descriptor.Digest}, nil
}

func decodeOneJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
