# rancher-token-revoker

The rancher-token-revoker watches your git repos for exposed rancher tokens. If any are discovered, it automatically 
deletes (or disables/warns depending on configuration) the exposed tokens.

## Description

### Feature Overview
- Define git repos to scan using a CRD
- Scan repos at custom-defined intervals
- Automatically delete/disable/warn (based on configuration) exposed rancher tokens
- Works with token hashing enabled or disabled

## Detailed Description
The rancher-token-revoker defines a CRD (GitRepoScans) which allows users to define specific git repos that will be watched for exposed rancher tokens.
These repos are then cloned by the application, and scanned using [gitleaks](https://github.com/zricethezav/gitleaks). Each time the repo is scanned, a pull is attempted first to ensure the repo is up-to-date. 

From there, the application attempts to delete/disable/warn about the tokens that it discovered. 
Since gitleaks is currently analyzing the commits rather than the raw file contents, even if users attempt to make the com

Users can define the following options for the controller:
- DefaultScanInterval: the default time between scans (in seconds, as an int) for GitRepoScans which don't specify a custom scan interval.
- RevokeMode: One of warn, disable, delete. Specifies the action to be taken with exposed tokens. Defaults to warn.
  - warn: Log the name of the exposed token with level warn.
  - disable: Update the token and set `token.enable` to false
  - delete: Remove the token entirely

Users can define the following options on the GitRepoScans CRD (see the [crd definition](config/crd/bases/management.cattle.io_gitreposcans.yaml) for all fields)
- ScanInterval: the time (in seconds as an int) between scans. If not specified (or is 0), uses the DefaultScanInterval
- RepoUrl: The url of the gitrepo to scan. Should be in the format of an `ssh` or `https` url which can be used to clone/pull the repo

*Note:* This will still work if you are using token hashing. 
However, there is a significant performance decrease when token hashing is enabled since the application needs to
compare exposed tokens against every token in the cluster. Make sure to keep this in mind when setting scan intervals.

## Developer information/usage

Information about developing locally/using the makefile can be found in the [kubebuilder readme](docs/kubebuilder_readme.md) 

Common commands include:
- `make`, for when you want to re-build the application. The application can then be run with `./bin/manager`
- `make install`, for when you need to install the relevant crds into the cluster before running the application.
- `make manifests`, for when you make a change to the crds and need to re-generate their definitions