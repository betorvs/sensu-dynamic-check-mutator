# sensu-dynamic-check-plugin

[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/betorvs/sensu-dynamic-check-mutator)
![Go Test](https://github.com/betorvs/sensu-dynamic-check-mutator/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/betorvs/sensu-dynamic-check-mutator/workflows/goreleaser/badge.svg)

## Table of Contents
- [Overview](#overview)
- [Usage](#usage)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Mutator definition](#mutator-definition)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
- [Contributing](#contributing)

## Overview

The sensu-dynamic-check-plugin is a [Sensu Mutator][1] that parse labels from sensu events and creates a dynamic check in Sensu Backend and add event.check.annotation `io.sensu.remediation.config.actions` with these values then it can be scheduled by [sensu-remediation-handler][4]

## Usage

```bash
Sensu Dynamic Check Mutator creates sensu check based on template

Usage:
  sensu-dynamic-check-mutator [flags]
  sensu-dynamic-check-mutator [command]

Available Commands:
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -B, --api-backend-host string                  Sensu Go Backend API Host (e.g. 'sensu-backend.example.com') (default "127.0.0.1")
  -k, --api-backend-key string                   Sensu Go Backend API Key
  -P, --api-backend-pass string                  Sensu Go Backend API Password (default "P@ssw0rd!")
  -p, --api-backend-port int                     Sensu Go Backend API Port (e.g. 4242) (default 8080)
  -u, --api-backend-user string                  Sensu Go Backend API User (default "admin")
  -c, --check-config string                      Json template for Sensu Check
      --command-arguments-template string        Template for Sensu Check Command (default "{{ range $key, $value := . }} {{ $key }} {{ $value }}{{ end }}")
      --command-bool-arguments-template string   Template for Sensu Check Command (default "{{ range $value := . }} {{ $value }}{{ end }}")
      --command-handler string                   Handler used to post the result (default "default")
      --default-check-suffix-name string         Default suffix name for unpublished checks (default "dynamic")
  -h, --help                                     help for sensu-dynamic-check-mutator
  -i, --insecure-skip-verify                     skip TLS certificate verification (not recommended!)
  -s, --secure                                   Use TLS connection to API
  -t, --trusted-ca-file string                   TLS CA certificate bundle in PEM format

Use "sensu-dynamic-check-mutator [command] --help" for more information about a command.
```

## Configuration

We add a json inside `--check-config`:

```json
[
  {
    "name": "describe-resource",
    "command": "${{assetPath \"kubectl\"}}/kubernetes/client/bin/kubectl describe",
    "bool_args": [
      "--no-headers"
    ],
    "arguments": ["daemonset","deployment","pod","statefulset","node"],
    "options": {
        "--namespace": "namespace"
    },
    "match_labels": {
        "sensu-alertmanager-events": "owner"
    },
    "sensu_assets": [
        "kubectl"
    ]
  }
]
```

In these example we use one event imported by [sensu-alertmanager-events][5] and we installed kubectl using assets.

```yml
type: Asset
api_version: core/v2
metadata:
  name: kubectl
  namespace: default
spec:
  sha512:  081472833601aa4fa78e79239f67833aa4efcb4efe714426cd01d4ddf6f36fbf304ef7e1f5373bff0fdff44a845f7560165c093c108bd359b5ab4189f36b1f2f
  url: https://dl.k8s.io/v1.20.0/kubernetes-client-linux-amd64.tar.gz
```

And it will create one annotation like:

```
"io.sensu.remediation.config.actions": "[{\"request\":\"KubeDaemonSetRolloutStuck-kube-system-filebeat-describe-resource-dynamic\",\"occurrences\":[1],\"severities\":[2],\"subscriptions\":[\"entity:k8s.dev.local\"]}]"
```

And one check called: `KubeDaemonSetRolloutStuck-kube-system-filebeat-describe-resource-dynamic` with command `${{assetPath \"kubectl\"}}/kubernetes/client/bin/kubectl describe --namespace kube-system daemonset filebeat-audit`.


### Asset registration

[Sensu Assets][2] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```
sensuctl asset add betorvs/sensu-dynamic-check-mutator
```

If you're using an earlier version of sensuctl, you can find the asset on the [Bonsai Asset Index][https://bonsai.sensu.io/assets/betorvs/sensu-dynamic-check-mutator].

### Mutator definition

```yml
---
type: Mutator
api_version: core/v2
metadata:
  name: sensu-dynamic-check-mutator
  namespace: default
spec:
  command: >-
    sensu-dynamic-check-mutator -c "[{\"name\":\"describe-resource\",\"command\":\"${{assetPath \\\"kubectl\\\"}}/kubernetes/client/bin/kubectl describe\",\"bool_args\":[\"--no-headers\"],\"arguments\":[\"daemonset\",\"deployment\",\"pod\",\"statefulset\",\"node\"],\"options\":{\"--namespace\":\"namespace\"},\"match_labels\":{\"sensu-alertmanager-events\":\"owner\"},\"sensu_assets\":[\"kubectl\"]}]"
  runtime_assets:
  - betorvs/sensu-dynamic-check-mutator
```

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the sensu-dynamic-check-mutator repository:

```
go build
```

## Additional notes

## Contributing

For more information about contributing to this plugin, see [Contributing][3].

[1]: https://docs.sensu.io/sensu-go/latest/reference/mutators/
[2]: https://docs.sensu.io/sensu-go/latest/reference/assets/
[3]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
[4]: https://github.com/sensu/sensu-remediation-handler
[5]: https://github.com/betorvs/sensu-alertmanager-events

