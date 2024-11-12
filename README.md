# IDS-Cyber Ansible Playbooks

This repository contains Ansible playbooks for setting up an Intrusion Detection System (IDS) and other cybersecurity measures.

# [⚠️ READ THE FULL REPORT ⚠️](FULL_REPORT.md)

## Prerequisites

- Ansible installed on your control machine
- Target machines accessible via SSH
- Sudo privileges on target machines

## Setup

1. Clone this repository:
   ```
   git clone https://github.com/ozeliurs/ids-cyber.git
   cd ids-cyber
   ```

2. Update the `inventory.ini` file with your target machines' IP addresses and SSH credentials.

## Running the Playbooks

Run the playbooks in the following order:

1. **iptables**:
   ```
   ansible-playbook -i inventory.ini iptables.yaml
   ```
   This playbook configures iptables rules for basic network security.

2. **proxy**:
   ```
   ansible-playbook -i inventory.ini proxy.yaml
   ```
   This playbook sets up Apache2 with SSL and proxy configurations.

3. **modsecurity**:
   ```
   ansible-playbook -i inventory.ini modsecurity.yaml
   ```
   This playbook installs and configures ModSecurity for Apache2.

4. **snort**:
   ```
   ansible-playbook -i inventory.ini snort.yaml
   ```
   This playbook installs and configures Snort IDS.

5. **fail2ban**:
   ```
   ansible-playbook -i inventory.ini fail2ban.yaml
   ```
   This playbook sets up Fail2ban for intrusion prevention.

## Notes

- Ensure that you have the necessary permissions and access to run these playbooks on your target machines.
- Review and adjust the configurations in each playbook to match your specific requirements before running them.
- It's recommended to test these playbooks in a non-production environment first.

## Troubleshooting

If you encounter any issues:
- Check the Ansible output for error messages
- Verify network connectivity to your target machines
- Ensure that the target machines meet all prerequisites
- Review the logs on the target machines for more detailed error information

For more information on each playbook, refer to the comments within the YAML files.
