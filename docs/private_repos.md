## Overview

There are two supported methods of private auth, http basic (username/password) and ssh keys. Both methods require you to create a secret (with the appropriate type) in the namespace that the revoker is installed in (usually cattle-revoker-system). The revoker only has permission to get secrets in the namespace it is installed in as a security best practice, so while you can create ScanConfigurations in any namespace, you will need to create these secrets in the namespace that the revoker is installed in.

You can then specify the secret as either part of the individual scan configuration or the configuration for the controller. As a best practice, it's a good idea to create only one secret (generally an ssh key), which you specify as part of the controller/chart. This secret should be configured to have access to each repo that you want to scan (either by associating the secret with a bot account that has access to each repo, or by adding the secret to the repo directly).

Refer to the following github docs for examples on the use of ssh keys for auth:
- [Deploy Keys](https://docs.github.com/en/developers/overview/managing-deploy-keys#deploy-keys)
- [Adding SSH Keys to a user account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)

You can force the revoker to use only public authentication when accessing a specific repo. This can be useful when you have configured the revoker to use a particular secret by default, but need to scan a public repo which will not accept the previously configured form of auth.

### SSH Keys

First, generate an ssh key with a command like the below. 

```bash
ssh-keygen -t ed25519
```

Notes:
- Not every provider will take every type of key. Refer to your provider documentation (e.x. [for github](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent#generating-a-new-ssh-key)) for exact steps on how to run this command
- Do not use a passphrase with the key. Keys encrypted with a passphrase will not work with the application (in this case, since the passphrase would also needed to be provided to the documentation, using a passphrase would not increase the effective security of your key from the application's perspective)

Second, convert your key to a format acceptable to k8s:

```bash
cat $PRIV_KEY_PATH | base64 | tr -d '\n'
```

Third, use the following yaml as a template to create the secret to store your key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: $KEY_NAME
  namespace: cattle-revoker-system
type: kubernetes.io/ssh-auth
data:
  ssh-privatekey: $BASE_64_KEY
```
Using kubectl, you can create this using `kubectl create -f example.yaml`, assuming the above contents where saved to `example.yaml`.

As seen above, the secret will need to be of type `kubernetes.io/ssh-auth`. Consult the [kubernetes docs](https://kubernetes.io/docs/concepts/configuration/secret/#ssh-authentication-secrets) for more information on using/creating secrets of this type. 

Be sure to replace the `$KEY_NAME` with the name of the key, and `$BASE_64_KEY` with the value of the key as produced in the second step.

Lastly configure a repo scan to use this key:

```yaml
apiVersion: management.cattle.io/v3
kind: GitRepoScan
metadata:
  name: $SCAN_NAME
  namespace: $SCAN_NS
spec:
  repoUrl: $GIT_REPO_URL 
  scanIntervalSeconds: 600
  repoSecretName: $KEY_NAME
```
Using kubectl, you can create this using `kubectl create -f example2.yaml`, assuming the above contents where saved to `example2.yaml`.

Since this repo was configured to use an ssh key as the secret, be sure that the provided repoUrl (replacing `$GIT_REPO_URL`) is in ssh format (e.x. `git@github.com:MbolotSuse/rancher-token-revoker.git`).

### HTTP Basic auth

Note: The ssh approach is generally more secure than this approach. It's recommended that you use that approach. 

This essentially requires that you provide a username/password from a user with access to the git repo. It's recommended that you attempt to scope these permissions. Some git providers will allow you to generate tokens which you can use to access these repos. It's recommended that if you  

For example, github allows the creation of [Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) which allow you to grant access only to select private repos. In the case of github, you will need to grant at least `Read only` access to `Content` to use the PAT with this tool.

First, generate the password/token.

Next, using the below yaml format, create the secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: $SECRET_NAME
  namespace: cattle-revoker-system
type: kubernetes.io/basic-auth
stringData:
  username: $USERNAME
  password: $PASSWORD
```
You don't need to base64 encode username or password, the raw value should work fine.

Using kubectl, you can create this using `kubectl create -f example.yaml`, assuming the above contents where saved to `example.yaml`.

Lastly, configure a repo scan to use te the secret:

```yaml
apiVersion: management.cattle.io/v3
kind: GitRepoScan
metadata:
  name: $SCAN_NAME
  namespace: $SCAN_NS
spec:
  repoUrl: $GIT_REPO_URL 
  scanIntervalSeconds: 600
  repoSecretName: $KEY_NAME
```

Using kubectl, you can create this using `kubectl create -f example2.yaml`, assuming the above contents where saved to `example2.yaml`.

Since this repo was configured to use a http basic auth as the secret, be sure that the provided repoUrl (replacing `$GIT_REPO_URL`) is in https format (e.x. `https://github.com/MbolotSuse/rancher-token-revoker.git`).
