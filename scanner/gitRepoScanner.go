package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mbolotsuse/rancher-token-revoker/errors"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/go-git/go-git/v5"
)

const basePath = "/tmp/repos"

type GitRepoScanner struct {
	RepoUrl string

	repo *git.Repository
}

// Start initializes the repo scanner and does the initial repo clone
func (g *GitRepoScanner) Start() error {
	err := initializeTargetDir(g.RepoUrl)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to initilize base dir %s", err.Error()), errors.InternalError)
	}
	repoId := createRepoId(g.RepoUrl)
	repoPath := filepath.Join(basePath, repoId)

	repo, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL: g.RepoUrl,
	})
	if err != nil {
		return errors.New(fmt.Sprintf("unable to clone repo %s", err.Error()), errors.InternalError)
	}
	g.repo = repo
	return nil
}

// Scan initializes a scan, returning a slice of findings or an error (if the process failed). Currently does a pull
// on every scan
func (g *GitRepoScanner) Scan() ([]report.Finding, error) {
	repoId := createRepoId(g.RepoUrl)
	repoPath := filepath.Join(basePath, repoId)

	wt, err := g.repo.Worktree()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to load worktree to refresh git repo %s", err), errors.InternalError)
	}
	err = wt.Pull(&git.PullOptions{})
	// if we got an error and are unable to pull the latest changes, return an error and don't evaluate this round
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return nil, errors.New(fmt.Sprintf("unable to refresh git repo %s", err), errors.InternalError)
	}
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"rancher-token-value": tokenRule,
		},
	}

	detector := detect.NewDetector(cfg)
	findings, err := detector.DetectGit(repoPath, "", detect.DetectType)
	if err != nil {
		return nil, errors.New(err.Error(), errors.InternalError)
	}
	return findings, nil
}

// Stop stops the scanner and removes the cloned repo
func (g *GitRepoScanner) Stop() error {
	repoId := createRepoId(g.RepoUrl)
	repoPath := filepath.Join(basePath, repoId)
	err := os.RemoveAll(repoPath)
	if err != nil {
		return errors.New(err.Error(), errors.InternalError)
	}
	return nil
}

// initializeTargetDir initializes the target directory and the related dependencies.
func initializeTargetDir(repoUrl string) error {
	baseDir, err := os.Stat(basePath)
	if err != nil {
		// if the baseDir doesn't exist, make a new one
		if os.IsNotExist(err) {
			createErr := os.MkdirAll(basePath, 0700)
			if createErr != nil {
				return fmt.Errorf("unable to create base directory %w", createErr)
			}
			// re-stat baseDir so our later call can verify that it is a directory
			baseDir, err = os.Stat(basePath)
			if err != nil {
				return fmt.Errorf("unable to verify baseDir was created %w", err)
			}
		} else {
			return err
		}
	}
	// baseDir exists, validate that it is a directory
	if !baseDir.IsDir() {
		return fmt.Errorf("base directory already initialized as non-dir")
	}

	repoId := createRepoId(repoUrl)
	repoPath := filepath.Join(basePath, repoId)
	_, err = os.Stat(repoPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unable to check for existence of target directory %w", err)
		}
	} else {
		err = os.RemoveAll(repoPath)
		if err != nil {
			return fmt.Errorf("unable to remove current directory at target path %w", err)
		}
	}
	return nil
}

// createRepoId creates the unique id for a given repo url
func createRepoId(repoUrl string) string {
	hash := sha256.Sum256([]byte(repoUrl))
	return hex.EncodeToString(hash[:])
}
