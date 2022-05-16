Role Name
=========

Adds all hosts in playbook to the known_hosts file on the controller.

Example Playbook
----------------

    - name: Add known to knowns hosts
      hosts: servers
      gather_facts: no
      serial: 1
      vars:
        ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
        ansible_become_method: sudo
      roles:
        - add_known_hosts

License
-------

BSD
