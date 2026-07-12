package main

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func TestDockerTarScratchArchiveIsDeterministicAndOrdered(t *testing.T) {
	inputs := []DockerScratchInput{{Path: "a/input", Bytes: []byte("a")}, {Path: "z/input", Bytes: []byte("z")}}
	first, err := dockerScratchTar(inputs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dockerScratchTar(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("scratch archives differ")
	}
	reader := tar.NewReader(bytes.NewReader(first))
	for _, want := range []string{"a/input", "z/input"} {
		header, err := reader.Next()
		if err != nil || header.Name != want || header.Mode != 0o600 {
			t.Fatalf("header = %#v, %v; want %q mode 0600", header, err, want)
		}
	}
}

func TestDockerTarRejectsUnsafeOrOversizedResults(t *testing.T) {
	tests := []struct {
		name   string
		header tar.Header
		data   []byte
		limit  int64
	}{
		{name: "traversal", header: tar.Header{Name: "../result", Mode: 0o600, Size: 1}, data: []byte("x"), limit: 2},
		{name: "link", header: tar.Header{Name: "result", Typeflag: tar.TypeSymlink, Linkname: "target"}, limit: 2},
		{name: "oversize", header: tar.Header{Name: "result", Mode: 0o600, Size: 2}, data: []byte("xx"), limit: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			if err := writer.WriteHeader(&tt.header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(tt.data); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := extractDockerResult(archive.Bytes(), tt.limit); err == nil {
				t.Fatal("extractDockerResult() succeeded; want error")
			}
		})
	}
}

func TestDockerTarAcceptsOnlyOneRegularResult(t *testing.T) {
	archive, err := dockerResultTar([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := extractDockerResult(archive, 2)
	if err != nil || string(result) != "ok" {
		t.Fatalf("extractDockerResult() = %q, %v", result, err)
	}
}

func TestLimitedCaptureBoundsEachStream(t *testing.T) {
	if got, err := limitedCapture(strings.NewReader("abc"), 3); err != nil || string(got) != "abc" {
		t.Fatalf("limitedCapture() = %q, %v", got, err)
	}
	if _, err := limitedCapture(strings.NewReader("abcd"), 3); err == nil {
		t.Fatal("limitedCapture() succeeded over limit")
	}
}
