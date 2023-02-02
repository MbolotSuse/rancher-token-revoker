package org

import (
	"context"
	"fmt"

	"github.com/google/go-github/v50/github"
	"golang.org/x/oauth2"
)

const (
	// DefaultBaseURL is the base url for the public github instance. Taken from: https://github.com/google/go-github/blob/2094f991592201d301feec818d413c136537732c/github/github.go#L34
	DefaultBaseURL = "https://api.github.com/"
	// DefaultUploadURL is the upload url for the public github instance. Taken from: https://github.com/google/go-github/blob/2094f991592201d301feec818d413c136537732c/github/github.go#L36
	DefaultUploadURL = "https://uploads.github.com/"
)

type GithubOrgScanner struct {
	client *github.Client
}

func NewGithubOrgScanner(baseURL string, uploadURL string, token string) (*GithubOrgScanner, error) {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})
	httpClient := oauth2.NewClient(context.Background(), tokenSource)
	githubClient, err := github.NewEnterpriseClient(baseURL, uploadURL, httpClient)
	if err != nil {
		return nil, err
	}
	return &GithubOrgScanner{
		client: githubClient,
	}, nil
}

// ListRepoURLs returns a slice of repo urls (in http or ssh format depending on repoType)
func (g *GithubOrgScanner) ListRepoURLs(orgPath string, repoType RepoType) ([]string, error) {
	if repoType != RepoTypeSSH && repoType != RepoTypeHTTP {
		return nil, fmt.Errorf("unrecognized repo type %d", repoType)
	}
	var repoUrls []string
	page := 1
	repoUrls, lastPage, err := g.listRepoUrlsPaginated(page, orgPath, repoType)
	if err != nil {
		return nil, err
	}
	for page < lastPage {
		page++
		newRepos, newLastPage, err := g.listRepoUrlsPaginated(page, orgPath, repoType)
		if err != nil {
			return nil, err
		}
		lastPage = newLastPage
		repoUrls = append(repoUrls, newRepos...)
	}
	return repoUrls, nil
}

// listRepoUrlsPaginated gets the result of a repoListByOrg assuming pagination
func (g *GithubOrgScanner) listRepoUrlsPaginated(page int, org string, repoType RepoType) ([]string, int, error) {
	var repoUrls []string
	repos, response, err := g.client.Repositories.ListByOrg(context.Background(), org, &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page: page,
		},
	})
	if err != nil {
		return nil, 0, err
	}
	for _, repo := range repos {
		switch repoType {
		case RepoTypeHTTP:
			repoUrls = append(repoUrls, *repo.CloneURL)
		case RepoTypeSSH:
			repoUrls = append(repoUrls, *repo.SSHURL)
		}
	}
	return repoUrls, response.LastPage, nil
}
