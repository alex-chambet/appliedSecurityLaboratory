# AppSecLab
Repository for the Applied Security Lab project at ETHZ

## VM passwords
For conveniance the VM passwords are the VM name (e.g. the `ca_core` VM has password `ca_core`), but note that on all machines (except client) normal users cannot sudo. Instead, use the command "su" to become root. The root password for each machine is different and can be found in the password manager (see below).

## Client VM
The Client VM has access to a password manager that contains all the useful passwords (or private keys) for the different user, etc. To access them you can run:
`$sudo keppassxc` in a terminal and use the `/home/client/Desktop/passwords/passwords.kdbx` database with `asl` as master key.

### Warning
In order to avoid certificate problem, make sure that all VM have the same time.
