package vault

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxScopeTraversalSteps = 128

var ErrScopeDetectionFailed = errors.New("scope detection failed")

func DetectScope(startDir string) (Scope, error) {
	root, hasGit, err := findProjectRoot(startDir)
	if err != nil {
		return Scope{}, err
	}

	canonicalRoot, err := canonicalPath(root)
	if err != nil {
		return Scope{}, fmt.Errorf("%w: canonicalize root: %v", ErrScopeDetectionFailed, err)
	}

	if hasGit {
		remote, err := canonicalGitOrigin(root)
		if err == nil && remote != "" {
			return Scope{
				ID:        remote,
				Label:     filepath.Base(canonicalRoot),
				Path:      canonicalRoot,
				GitBacked: true,
			}, nil
		}
	}

	return Scope{
		ID:        "local:" + hashPath(canonicalRoot),
		Label:     filepath.Base(canonicalRoot),
		Path:      canonicalRoot,
		GitBacked: false,
	}, nil
}

func findProjectRoot(startDir string) (string, bool, error) {
	dir, err := canonicalPath(startDir)
	if err != nil {
		return "", false, fmt.Errorf("%w: canonicalize start dir: %v", ErrScopeDetectionFailed, err)
	}

	current := dir
	for steps := 0; steps < maxScopeTraversalSteps; steps++ {
		hasGit, err := hasGitMarker(current)
		if err != nil {
			return "", false, err
		}
		if hasGit {
			return current, true, nil
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return dir, false, nil
}

func hasGitMarker(dir string) (bool, error) {
	for _, candidate := range []string{".git"} {
		path := filepath.Join(dir, candidate)
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return false, fmt.Errorf("%w: stat git marker: %v", ErrScopeDetectionFailed, err)
		}
		if info.IsDir() || info.Mode().IsRegular() {
			return true, nil
		}
	}

	return false, nil
}

func canonicalPath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	evaluatedPath, err := filepath.EvalSymlinks(absolutePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return absolutePath, nil
		}
		return "", err
	}

	return evaluatedPath, nil
}

func canonicalGitOrigin(root string) (string, error) {
	cmd := exec.Command("git", "-C", root, "config", "--get", "remote.origin.url")
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", nil
		}
		return "", fmt.Errorf("%w: read git origin: %v", ErrScopeDetectionFailed, err)
	}

	return canonicalizeGitRemote(strings.TrimSpace(string(output)))
}

func canonicalizeGitRemote(remote string) (string, error) {
	trimmedRemote := strings.TrimSpace(remote)
	if trimmedRemote == "" {
		return "", nil
	}

	if strings.HasPrefix(trimmedRemote, "git@") {
		hostPath := strings.TrimPrefix(trimmedRemote, "git@")
		host, path, ok := strings.Cut(hostPath, ":")
		if !ok {
			return "", fmt.Errorf("%w: malformed ssh remote %q", ErrScopeDetectionFailed, remote)
		}
		return normalizeRemoteHostPath(host, path), nil
	}

	parsed, err := url.Parse(trimmedRemote)
	if err != nil {
		return "", fmt.Errorf("%w: parse remote %q: %v", ErrScopeDetectionFailed, remote, err)
	}

	switch parsed.Scheme {
	case "https", "http", "ssh":
		host := parsed.Hostname()
		path := strings.TrimPrefix(parsed.Path, "/")
		return normalizeRemoteHostPath(host, path), nil
	default:
		return "", fmt.Errorf("%w: unsupported remote scheme %q", ErrScopeDetectionFailed, parsed.Scheme)
	}
}

func normalizeRemoteHostPath(host, path string) string {
	normalizedHost := strings.ToLower(strings.TrimSpace(host))
	normalizedPath := strings.TrimSuffix(strings.TrimSpace(path), ".git")
	normalizedPath = strings.TrimPrefix(normalizedPath, "/")
	return normalizedHost + "/" + normalizedPath
}

func hashPath(path string) string {
	// Simple stable placeholder until the scoped vault implementation is complete.
	// The exact digest algorithm is internal and not user-facing.
	var hash uint64 = 1469598103934665603
	const prime uint64 = 1099511628211
	for i := 0; i < len(path); i++ {
		hash ^= uint64(path[i])
		hash *= prime
	}
	return fmt.Sprintf("%016x", hash)
}
