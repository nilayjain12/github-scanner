package github

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// FetchFile fetches the file content from a GitHub repository or a local path.
// For GitHub sources, it will retry up to 2 attempts if the HTTP call fails.
func FetchFile(source, file string) ([]byte, error) {
	var content []byte
	var err error

	if strings.HasPrefix(source, "http") {
		// Construct raw file URL for GitHub.
		fileRawURL := strings.Replace(source, "github.com", "raw.githubusercontent.com", 1) + "/main/" + file

		var resp *http.Response
		const maxAttempts = 2
		var attempt int

		for attempt = 1; attempt <= maxAttempts; attempt++ {
			resp, err = http.Get(fileRawURL)
			if err != nil {
				// Log and retry if not the last attempt.
				if attempt < maxAttempts {
					time.Sleep(1 * time.Second)
					continue
				}
				return nil, fmt.Errorf("failed to fetch file %s (attempt %d): %v", file, attempt, err)
			}

			if resp.StatusCode != http.StatusOK {
				// Close the response and retry if not the last attempt.
				resp.Body.Close()
				if attempt < maxAttempts {
					time.Sleep(1 * time.Second)
					continue
				}
				return nil, fmt.Errorf("failed to fetch file %s (attempt %d): received status %d", file, attempt, resp.StatusCode)
			}

			// Successful HTTP call.
			break
		}

		defer resp.Body.Close()

		content, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %v", file, err)
		}
	} else {
		// For local files.
		filePath := filepath.Join(source, file)
		content, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %v", file, err)
		}
	}

	return content, nil
}
