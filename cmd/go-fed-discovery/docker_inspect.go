package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type dockerContainerInspectDocument struct {
	ID     string `json:"Id"`
	Config struct {
		Image string   `json:"Image"`
		User  string   `json:"User"`
		Cmd   []string `json:"Cmd"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		Memory         int64    `json:"Memory"`
		NanoCPUs       int64    `json:"NanoCpus"`
		NetworkMode    string   `json:"NetworkMode"`
		CapDrop        []string `json:"CapDrop"`
	} `json:"HostConfig"`
	State struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	} `json:"State"`
}

func dockerContainerInspectArgs(id string) []string {
	return []string{"--host", dockerLocalUnixEndpoint, "--config", "/var/empty", "container", "inspect", "--format", "{{json .}}", id}
}

func parseDockerContainerInspect(output []byte) (dockerContainerInspectDocument, error) {
	var documents []dockerContainerInspectDocument
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(&documents); err != nil {
		return dockerContainerInspectDocument{}, fmt.Errorf("docker container inspect must return structured JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return dockerContainerInspectDocument{}, errors.New("docker container inspect returned multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return dockerContainerInspectDocument{}, fmt.Errorf("docker container inspect trailing data: %w", err)
	}
	if len(documents) != 1 || !validDockerContainerID(documents[0].ID) {
		return dockerContainerInspectDocument{}, errors.New("docker container inspect must return one normalized container")
	}
	return documents[0], nil
}

func validDockerContainerID(value string) bool {
	return len(value) == dockerDigestHexLength && isLowerHex(value)
}

func validateDockerContainerConstraints(document dockerContainerInspectDocument, id string, request DockerRunRequest) error {
	if document.ID != id {
		return errors.New("docker container inspect ID does not match created container")
	}
	if document.Config.Image != request.Image || document.Config.User != dockerContainerUser || !equalStrings(document.Config.Cmd, request.Command) {
		return errors.New("docker container image, user, or command does not match request")
	}
	if !document.HostConfig.ReadonlyRootfs || document.HostConfig.Memory != request.MemoryBytes || document.HostConfig.NanoCPUs != dockerNanoCPUs(request.CPUs) || document.HostConfig.NetworkMode != "none" || !equalStrings(document.HostConfig.CapDrop, []string{"ALL"}) {
		return errors.New("docker container constraints do not match request")
	}
	return nil
}

func dockerNanoCPUs(cpus string) int64 {
	wholeText, fractionText, found := strings.Cut(cpus, ".")
	whole, err := strconv.ParseInt(wholeText, 10, 64)
	if err != nil || whole < 0 {
		return -1
	}
	if whole > (int64(^uint64(0)>>1)-999_999_999)/1_000_000_000 {
		return -1
	}
	if !found {
		return whole * 1_000_000_000
	}
	if fractionText == "" || len(fractionText) > 9 {
		return -1
	}
	fraction, err := strconv.ParseInt(fractionText, 10, 64)
	if err != nil {
		return -1
	}
	for index := len(fractionText); index < 9; index++ {
		fraction *= 10
	}
	return whole*1_000_000_000 + fraction
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
