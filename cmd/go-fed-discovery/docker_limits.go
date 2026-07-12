package main

import (
	"bytes"
	"errors"
	"io"
)

// limitedCapture drains one stream without allowing it to exceed its fixed
// bound. It continues reading through the first byte beyond the limit so that
// callers can safely wait for a concurrently drained sibling stream.
func limitedCapture(reader io.Reader, maximum int64) ([]byte, error) {
	if reader == nil {
		return nil, nil
	}
	if maximum <= 0 {
		return nil, errors.New("capture limit must be positive")
	}
	var captured bytes.Buffer
	chunk := make([]byte, 32<<10)
	var total int64
	for {
		count, readErr := reader.Read(chunk)
		if count > 0 {
			if int64(count) > maximum-total {
				return nil, errors.New("container stream exceeds max_output_bytes")
			}
			if _, err := captured.Write(chunk[:count]); err != nil {
				return nil, err
			}
			total += int64(count)
		}
		if readErr == io.EOF {
			return captured.Bytes(), nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}
