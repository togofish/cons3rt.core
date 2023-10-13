Role Name
=========

Changes created user and root password and unlocks ansible user if created user password is expired.

Requirements
------------

A CONS3RT provisioned node that has not altered the user created on deployment.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    ---
    # grabs the expired cons3rt created password and changes it to:
    # --extra-vars "new_password=foopassword"
    # you will also need:
    # --extra-vars "node=foonode"
    - name: Changed expired password
      hosts: '{{ node }}'
      gather_facts: no
      serial: 1
      vars:
        ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
        ansible_become_method: sudo
      roles:
        - change_expired_password

License
-------

BSD
