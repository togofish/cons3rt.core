add_host_entry
=========

Adds host entry for all hosts in playbook using the default IP address and the ansible role name.

Example Playbook
----------------

    - hosts: servers
      roles:
         - add_host_entry