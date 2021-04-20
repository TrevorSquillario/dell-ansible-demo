# DellEMC OpenManage Ansible Demo

## Getting Started
1. Setup Python Virtual Environment (optional but recommended)
```
pip install virtualenv
mkdir ~/venv
python -m virtualenv ~/venv/ansible-dell
source ~/venv/ansible-dell/bin/activate
```

2. Install Dependencies
```
pip install omsdk pyvmomi ansible
ansible-galaxy install -r requirements.yml
```

3. Save the passphrase in a file called .vault_password. This file is referenced in the `ansible.cfg` config file `vault_password_file` setting.
```
echo "abc123" > .vault_password
```

4. Create an encrypted vault file (vault.yml) to store passwords. This will use the passphrase from the `.vault_password` file.
```
ansible-vault create vault.yml
```
These variables will be used in the examples and should be filled in.
```
# iDRAC Credentials
vault_oob_username: ""
vault_oob_password: ""
# OME Credentials
vault_ome_username: ""
vault_ome_password: ""

# Optional
vault_share_host: ""
vault_vcenter_host: ""
vault_vcenter_username: ""
vault_vcenter_password: ""
vault_esxi_username: ""
vault_esxi_password: ""
```

5. Update the inventory `inventory/us-west/hosts` with your hosts. Two host variables are used: `oob_host` to identify the out-of-band (iDRAC) IP or hostname and `service_tag` which is used in the ome_* modules. 
```
[group-name]
hostname oob_host=<iDRAC IP or Hostname> service_tag=<Service Tag>
```

6. Update global variables. Edit the `inventory/us-west/all/00_all.yml` file and update the `default_ome_host` variable. This can be the OpenManage Enterprise server or MX7000 Chassis for OpenManage Modular.
```
default_ome_host: "mx7000-chassis.example.com"
```

7. Execute a playbook
```
ansible-playbook -i inventory/us-west ome-device-info.yml
```

## Custom Modules
The `library` folder contains modules developed by myself which have not been officially released yet. These are to be used at you own risk.

## Inventory
Instead of maintaining all of your hosts within a single inventory file, an inventory can be maintained for each of your individual environments. Separate group_vars directories are also maintained. Symlinks can be used to share group variable files between environments. This can be used to separate environments (dev, test, prod) or physical locations (us-west, us-east).

Target multiple inventories by specifing the -i parameter again.
Ex: `ansible-playbook -i inventory/us-west -i inventory/us-east ome-device-info.yml`

You could also use a dynamic inventory script to query your internal inventory or a 3rd party provider. 
```
├── inventory
│   └── us-west
│       ├── group_vars
│       │   ├── all
│       │   │   └── 00_all.yml # Global variables, applies to all hosts
│       │   ├── mx-sleds.yml # Group variables, matches inventory group name
│       └── hosts # Static inventory file containing hosts and host_vars
```
