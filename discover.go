package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func resolveBinary(name string) string {
	if strings.ContainsAny(name, "/\\") {
		return name
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "bin", name)
		if runtime.GOOS == "windows" {
			candidate += ".exe"
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return name
}

func discoverSubdomains(domain, subfinderPath string) ([]string, error) {
	cmd := exec.Command(resolveBinary(subfinderPath), "-d", domain, "-silent")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run subfinder (%s): %w: %s", subfinderPath, err, strings.TrimSpace(errOut.String()))
	}
	return dedupLines(out.String()), nil
}

func liveHosts(inputs []string, httpxPath string, skipTLSVerify bool) ([]string, error) {
	args := []string{"-silent", "-no-color"}
	if skipTLSVerify {
		args = append(args, "-no-fallback")
	}
	cmd := exec.Command(resolveBinary(httpxPath), args...)
	cmd.Stdin = strings.NewReader(strings.Join(inputs, "\n"))
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run httpx (%s): %w: %s", httpxPath, err, strings.TrimSpace(errOut.String()))
	}
	return dedupLines(out.String()), nil
}

func dedupLines(text string) []string {
	seen := map[string]bool{}
	var result []string
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, s)
	}
	return result
}
