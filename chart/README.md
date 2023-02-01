## Application (i.e. non-standard) options

| Parameter                 | Default Value | Description                                                                                  |
| ------------------------- | ------------- | -------------------------------------------------------------------------------------------- |
| `revokerOptions.mode`     | "disable"     | ***string*** - Mode which determines action to take on exposed tokens. **warn, disable, delete** |
| `revokerOptions.defaultSecretName` | " "     | ***string*** - Name of the secret (in the same namespace the chart is installed in) which contains the default auth secret to use for private repos |
| `revokerOptions.defaultScanInterval` | 600 | ***int*** - Default interval (in seconds) between scans of a repo |


## Notes
- This chart requires [rancher](https://github.com/rancher/rancher/tree/release/v2.7/chart) to be installed before use, and will produce an error if you attempt to install the chart in a cluster where rancher is not running.
- By default, helm does not render CRDs when using `helm template`. To include them, use the `--include-crds`
- Helm does not remove CRDs when the chart is uninstalled. To remove the crds, you will need to manually remove (likely using `kubectl delete`) all of the CRDs defined the `crds` directory.
