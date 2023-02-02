package org

type RepoType int

const (
	RepoTypeHTTP RepoType = iota
	RepoTypeSSH
)
