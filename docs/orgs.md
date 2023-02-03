## Scanning an org

The GitOrgScan crd provides the capability to scan all of the repos belonging to an org. As of now, only github is supported.

1. Create an access token from your git provider.

For github, the org listing functionality uses the [Rest api](https://docs.github.com/en/rest?apiVersion=2022-11-28). Generate a [Fine-grained PAT](https://docs.github.com/en/enterprise-server@3.4/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) for your organization. Note that you will need to have `Metadata` level permissions on every repo that you want to scan that is a part of this org. You can control which repos in an org are included in the scan by only granting access to those repos.

2. Create a secret in the same namespace as the revoker.

### Github

In the case of github, use the below template to create a secret containing the token obtained in step one.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-token
  namespace: $RELEASE_NS 
type: management.cattle.io/github-token
stringData:
  accessToken: $TOKEN 
```

This secret contains two important fields, "type" and "stringData.accessToken". Both of these values must be properly set for this to work.

You can use the same secret as you intend to use for access to the repos, but keep in mind that: cloning a repo requires different permissions than scanning an org, and you will still need to create two separate secrets. See the docs on [private repos](private_repos.md) for more information on how to create the other secret for repo access. 


3. Create a GitOrgScan.

See the [sample](../config/samples/management_v3_gitorgscan.yaml) for a full example.

Notes:
- It's recommended that the scan interval for the org (`spec.orgScanConfig.orgScanInterval`) is set to a different, higher value than the repo scan interval (`spec.repoScanConfig.scanIntervalSeconds`). While an individual repo may have many commits in a short time frame, new repos in an org are comparatively rare.
- The repoScanConfig (`spec.repoScanConfig`) will be used for every repo in this org. You will need to make sure that the repo secret (`spec.repoScanConfig.repoSecretName`) can be used to clone each repo and that it works for the repoUrlType (`spec.orgScanConfig.repoUrlType`).

## Implementation Details

The org scan, on it's own, does relatively little work. It really just scans the org for repos, and then creates a GitRepoScan for each repo using the specified repoScanConfig. The ownership model between an OrgScan and the RepoScans that it creates is somewhat similar to the deployment/pod model. However, to avoid constantly refreshing the same repo on change, the OrgScan is not re-enqueued if you change a repoScan that it creates, It will, however, re-create the repoScan after the next orgScan refresh interval.
