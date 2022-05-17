.. _kubernetes.core.k8s_inventory:


*******************
cons3rt.core.cons3rt
*******************

**CONS3RT inventory source**



.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Fetch all deployment run details in active state
- Groups by cons3rt_role_name.
- Uses cons3rt.(yml|yaml) YAML configuration file to set parameter values.



Requirements
------------
The below requirements are needed on the local Ansible controller node that executes this inventory.

- CONS3RT >= 22.10
- python >= 3.9
- pyOpenSSL
- jmespath



Examples
--------

Recommended ansible.cfg file:

.. code-block:: text

    # config file for ansible -- https://ansible.com/
    # ===============================================

    [defaults]
    fact_caching_connection = /home/ansible/.cons3rt
    fact_caching_timeout = 604800

    # the entry below is required if you want password-less sudo
    [sudo_become_plugin]
    flags = -H -S
.. code-block:: yaml

    # File must be named cons3rt.yaml or cons3rt.yml

    plugin: cons3rt.core.cons3rt
    cache: True
    cache_plugin: jsonfile
    cert_file_path: /home/ansible/.cons3rt/my-cert.p12
    cons3rt_token: 123456789-1234-1234-1234-123456789012
    cert_password: my-cert-password
    cons3rt_url: https://api.cons3rt.com/rest
    compose:
      ansible_host: 'network_interfaces | selectattr("network_function", "equalto", "CONS3RT") | json_query("[0].internal_ip_address")'
    keyed_groups:
      - key: dr_name
        separator: ""
    groups:
      all_hosts: "My Deployment Run" in dr_name'
      group1: '"cons3rt_role_name" in system_role and "My Deployment Run" in dr_name|lower'
