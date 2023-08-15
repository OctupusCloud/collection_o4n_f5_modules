# Octupus Collection

Collection o4n_f5_modules includes imperative Ansible modules for BIG-IP from F5.  
By Randy Rozo

## Required

- Ansible >= 2.10  
- Collection: f5networks.f5_modules
- Python Library: 
  - bigsuds==1.0.6
  - suds

## Python Version Notice  

Collection only supports python 3.6 and above  

## Modules

- o4n_prune_disabled_node_from_date  
  Its main function is the ability to remove (or "prune") nodes that have been disabled since a specific date on BIG-IP  
- o4n_bigip_profile_persistence_dest_addr  
  Its main function is the ability to create, set, and remove profile persistence destination address on BIG-IP  
- o4n_bigip_profile_smtp  
  Its main function is the ability to create, set, and remove profile persistence smtp on BIG-IP  
- o4n_f5_dns_record_zonerunner  
  Manage DNS record on BIG-IP. The records managed here are primarily used for configuring DNS records on a BIG-IP ZoneRunner.  
- o4n_f5_dns_zone_zonerunner  
  Manage DNS zones on BIG-IP. The zones managed here are primarily used for configuring DNS on a BIG-IP ZoneRunner.  
- win_dns_record  
  Manage DNS record on Windows Server. The records managed here are primarily used for configuring DNS records on a Windows Server.  


