# Octupus Collection

Collection o4n_f5_modules includes imperative Ansible modules for BIG-IP from F5.  
By Randy Rozo

## Required

- Ansible >= 2.10  
- Collection: f5networks.f5_modules

## Python Version Notice  

Collection only supports python 3.6 and above  

## Modules

- o4n_prune_disabled_node_from_date  
  Its main function is the ability to remove (or "prune") nodes that have been disabled since a specific date on BIG-IP  
- o4n_bigip_profile_persistence_dest_addr  
  Its main function is the ability to create, set, and remove profile persistence destination address on BIG-IP  
- o4n_bigip_profile_smtp  
  Its main function is the ability to create, set, and remove profile persistence smtp on BIG-IP  
