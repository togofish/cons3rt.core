# CONS3RT Collection for Ansible

This repository hosts the `cons3rt.core` Ansible Collection.

The collection includes a variety of Ansible content to help automate the management of applications in CONS3RT environments.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.12.5**.

<!--end requires_ansible-->

## Python Support

* Collection supports 3.9+

## CONS3RT Version Support

This collection supports CONS3rt versions >=22.10.

## Included content

Click on the name of a plugin or module to view that content's documentation:

<!--start collection content-->
### Inventory plugins
| Name                                                                                                     | Description              |
|----------------------------------------------------------------------------------------------------------|--------------------------|
| [cons3rt.core.cons3rt](https://github.com/togofish/cons3rt.core/docs/cons3rt.core.cons3rt_inventory.rst) | CONS3RT inventory source |

<!--end collection content-->

## Installation and Usage

### Build

    ansible-galaxy collection build

### Installing the Collection from Ansible Galaxy

Before using the Kubernetes collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install cons3rt.core

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: cons3rt.core
    version: 0.1.9
```

## Publishing New Versions

Releases are automatically built and pushed to Ansible Galaxy for any new tag. Before tagging a release, make sure to do the following:

1. Update the version in the following places:
    1. The `version` in `galaxy.yml`
    2. This README's `requirements.yml` example

The process for uploading a supported release to Automation Hub is documented separately.

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.