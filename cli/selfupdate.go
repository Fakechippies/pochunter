package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Fakechippies/POC-Hunter/db"
	"github.com/Fakechippies/POC-Hunter/versioncanon"
	"github.com/spf13/cobra"
)

const repoReleasesAPI = "https://api.github.com/repos/Fakechippies/POC-Hunter/releases/latest"

func newSelfUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "selfupdate",
		Short: "Replace this binary with the latest GitHub release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelfUpdate(context.Background())
		},
	}
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func runSelfUpdate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	progressf("Checking for a new release...")
	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return err
	}
	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(db.AppVersion, "v")

	if current != "dev" && versioncanon.Compare(current, latest) >= 0 {
		successf("Already up to date (%s >= %s)", current, latest)
		return nil
	}

	asset, err := pickAsset(release)
	if err != nil {
		return err
	}
	progressf("Downloading %s...", asset.Name)

	binary, err := downloadAsset(ctx, asset.URL, asset.Name)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	if err := replaceBinary(exe, binary); err != nil {
		return err
	}
	successf("Updated %s -> %s. Rerun the tool to pick it up.", current, latest)
	return nil
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoReleasesAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release lookup failed with status %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("no releases published yet")
	}
	return &rel, nil
}

// pickAsset finds the release asset for this OS/arch. Recognizes plain
// binaries and .tar.gz archives named like pochunter_{os}_{arch}*.gz.
func pickAsset(release *ghRelease) (asset struct {
	Name string
	Size int64
	URL  string
}, err error) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	for _, a := range release.Assets {
		name := strings.ToLower(a.Name)
		if !strings.Contains(name, goos) || !strings.Contains(name, goarch) {
			continue
		}
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".gz") ||
			strings.HasSuffix(name, ".exe") || !strings.Contains(name, ".") {
			return struct {
				Name string
				Size int64
				URL  string
			}{a.Name, a.Size, a.URL}, nil
		}
	}
	return asset, fmt.Errorf("no release asset for %s/%s in release %s (looking for pochunter_%s_%s*)",
		goos, goarch, release.TagName, goos, goarch)
}

// downloadAsset fetches the asset and returns the raw binary bytes,
// extracting .tar.gz archives.
func downloadAsset(ctx context.Context, url, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}

	if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				return nil, fmt.Errorf("no binary found in archive")
			}
			if err != nil {
				return nil, err
			}
			if hdr.Typeflag == tar.TypeReg && !strings.Contains(hdr.Name, "/") {
				return io.ReadAll(tr)
			}
		}
	}
	return io.ReadAll(resp.Body)
}

// replaceBinary swaps the running executable atomically: the old binary is
// moved aside, the new one takes its place, and the old copy is removed.
func replaceBinary(target string, newBinary []byte) error {
	tmp := target + ".new"
	if err := os.WriteFile(tmp, newBinary, 0o755); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}
	old := target + ".old"
	if err := os.Rename(target, old); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("move old binary: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(old, target) // best-effort restore
		os.Remove(tmp)
		return fmt.Errorf("install new binary: %w", err)
	}
	_ = os.Remove(old)
	return nil
}
