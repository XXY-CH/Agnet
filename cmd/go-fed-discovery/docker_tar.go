package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
)

// dockerScratchTar produces the sole input archive accepted by `docker cp -`.
// The inputs were sorted and bounded by profile validation; this function still
// checks their shape so callers cannot bypass that boundary.
func dockerScratchTar(inputs []DockerScratchInput) ([]byte, error) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for _, input := range inputs {
		if err := validateDockerScratchPath(input.Path); err != nil {
			return nil, fmt.Errorf("invalid scratch archive path %q: %w", input.Path, err)
		}
		header := &tar.Header{
			Name:       input.Path,
			Mode:       0o600,
			Size:       int64(len(input.Bytes)),
			ModTime:    time.Unix(0, 0).UTC(),
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Uid:        0,
			Gid:        0,
			Format:     tar.FormatUSTAR,
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write scratch archive header: %w", err)
		}
		if _, err := writer.Write(input.Bytes); err != nil {
			return nil, fmt.Errorf("write scratch archive file: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish scratch archive: %w", err)
	}
	return archive.Bytes(), nil
}

// dockerResultTar is a compact helper for adapters and tests that need the
// canonical one-file response shape returned by `docker cp CONTAINER:/work/result -`.
func dockerResultTar(result []byte) ([]byte, error) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "result", Mode: 0o600, Size: int64(len(result)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}); err != nil {
		return nil, err
	}
	if _, err := writer.Write(result); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return archive.Bytes(), nil
}

// extractDockerResult accepts exactly one bounded regular result file. Docker
// emits the copied file as `result`; accepting no directories, links, metadata
// aliases, or sibling entries prevents tar extraction ambiguity.
func extractDockerResult(archive []byte, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("result limit must be positive")
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	var result []byte
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read result archive: %w", err)
		}
		entries++
		if entries != 1 || header.Name != "result" || header.Linkname != "" || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return nil, errors.New("result archive must contain exactly one regular result file")
		}
		if header.Size < 0 || header.Size > maximum {
			return nil, errors.New("result archive exceeds max_output_bytes")
		}
		result = make([]byte, header.Size)
		if _, err := io.ReadFull(reader, result); err != nil {
			return nil, fmt.Errorf("read result archive file: %w", err)
		}
	}
	if entries != 1 || result == nil {
		return nil, errors.New("result archive must contain exactly one regular result file")
	}
	return result, nil
}
