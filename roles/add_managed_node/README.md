Role Name
=========

Enables a newly provisioned node to be managed by ansible.

Requirements
------------

A CONS3RT provisioned node that has not altered the user created on deployment.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    ---
    - name: Add managed node
      hosts: '{{ node }}'
      gather_facts: no
      serial: 1
      vars:
      ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
      ansible_become_method: sudo
      roles:
        - add_managed_node
        - add_known_hosts

License
-------

BSD
