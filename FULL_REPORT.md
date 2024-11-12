# IDS Configuration Guide

## Step 1: Firewall Setup with `iptables`

1. **Install `iptables`**:

   ```bash
   sudo apt-get update
   sudo apt-get install iptables iptables-persistent
   ```

2. **Set Default Policies**:

   ```bash
   sudo iptables -P INPUT DROP
   sudo iptables -P FORWARD DROP
   sudo iptables -P OUTPUT DROP
   ```

3. **Allow DNS, ICMP, DHCP, and Loopback Traffic**:

   ```bash
   sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
   sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT
   sudo iptables -A OUTPUT -p icmp -j ACCEPT
   sudo iptables -A INPUT -p icmp -j ACCEPT
   sudo iptables -A OUTPUT -p udp --dport 67:68 -j ACCEPT
   sudo iptables -A INPUT -p udp --sport 67:68 -j ACCEPT
   sudo iptables -A INPUT -i lo -j ACCEPT
   sudo iptables -A OUTPUT -o lo -j ACCEPT
   ```

4. **Allow SSH and Web Service Access**:

   ```bash
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
   sudo iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
   sudo iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
   ```

5. **Allow Docker subnet communication**:

   ```bash
   sudo iptables -A INPUT -s 172.17.0.0/12 -j ACCEPT
   sudo iptables -A OUTPUT -d 172.17.0.0/12 -j ACCEPT
   ```

6. **Save iptables Configuration**:
   ```bash
   sudo iptables-save -f /etc/iptables/rules.v4
   ```

## Step 2: Setting up a Reverse Proxy and TLS Encryption

1. **Package Installation**:

	```bash
	sudo apt-get install apache2 easy-rsa
	```

2. **Easy-RSA Setup and Certificate Generation**:

	```bash
	# Create Easy-RSA directory
	sudo make-cadir /etc/easy-rsa

	# Initialize PKI
	cd /etc/easy-rsa
	./easyrsa init-pki

	# Generate CA certificate (non-interactive)
	./easyrsa build-ca nopass

	# Generate server certificate request
	./easyrsa --batch gen-req juice.ozeliurs.com nopass

	# Sign server certificate
	./easrsa --batch sign-req server juice.ozeliurs.com
	```

3. **Apache SSL Configuration**:

	```bash
	# Create SSL directory
	sudo mkdir /etc/apache2/ssl

	# Copy certificates to Apache directory
	sudo cp /etc/easy-rsa/pki/issued/juice.ozeliurs.com.crt /etc/apache2/ssl/
	sudo cp /etc/easy-rsa/pki/private/juice.ozeliurs.com.key /etc/apache2/ssl/

	# Enable required Apache modules
	sudo a2enmod ssl proxy proxy_http
	```

4. **Virtual Host Configuration**:
   Create file `/etc/apache2/sites-available/juice.ozeliurs.com.conf`:

   ```apache
   <VirtualHost *:80>
       ServerName juice.ozeliurs.com
       Redirect permanent / https://juice.ozeliurs.com/
   </VirtualHost>

   <VirtualHost *:443>
       SSLEngine on
       SSLCertificateFile /etc/apache2/ssl/juice.ozeliurs.com.crt
       SSLCertificateKeyFile /etc/apache2/ssl/juice.ozeliurs.com.key

       <Location />
           ProxyPass http://127.0.0.1:3000/
           ProxyPassReverse http://127.0.0.1:3000/
       </Location>

       <Location /premium>
           ProxyPass http://127.0.0.1:10000/
           ProxyPassReverse http://127.0.0.1:10000/
       </Location>

       ErrorLog /var/log/apache2/error.juice.ozeliurs.com.log
       CustomLog /var/log/apache2/access.juice.ozeliurs.com.log combined
   </VirtualHost>
   ```

5. **Enable Site and Restart Apache**:

   ```bash
   sudo a2ensite juice.ozeliurs.com
   sudo a2dissite 000-default
   sudo systemctl restart apache2
   ```

## Step 3: Setting up the Web Application Firewall (WAF) with ModSecurity

1. **Install ModSecurity**:

   ```bash
   # Install ModSecurity module for Apache
   sudo apt-get update
   sudo apt-get install libapache2-mod-security2

   # Enable ModSecurity module in Apache
   sudo a2enmod security2
   ```

2. **Configure ModSecurity**:

   ```bash
   # Copy recommended configuration
   sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

   # Enable audit engine
   sudo sed -i 's/SecAuditEngine .*/SecAuditEngine On/' /etc/modsecurity/modsecurity.conf
   ```

3. **Apply Changes**:

   ```bash
   # Restart Apache to apply ModSecurity changes
   sudo systemctl restart apache2
   ```

4. **Verify Installation**:

   ```bash
   # Check if ModSecurity is loaded
   apache2ctl -M | grep security

   # Check ModSecurity configuration
   cat /etc/modsecurity/modsecurity.conf | grep SecAuditEngine
   ```

## Step 4: Intrusion Detection System (IDS) Setup with Snort

## Step 4: Intrusion Detection System (IDS) Setup with Snort

1. **Install Snort**:

   ```bash
   sudo apt-get install snort
   ```

2. **Configure Custom Rules**:
   Add the following rule to `/etc/snort/rules/local.rules`:

   ```
   alert tcp any any -> any 22 (msg: "SSH Connection Attempt"; sid:10000001; rev:1;)
   ```

3. **Create Systemd Service**:
   Create file `/etc/systemd/system/alert-snort.service`:

   ```ini
   [Unit]
   Description=Snort IDS in alert mode
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/sbin/snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i [DEFAULT_INTERFACE]
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

   Note: `[DEFAULT_INTERFACE]` is automatically replaced with your system's default network interface.

4. **Enable and Start Snort Service**:

   ```bash
   # Reload systemd configuration
   sudo systemctl daemon-reload

   # Enable Snort service to start on boot
   sudo systemctl enable alert-snort

   # Start Snort service
   sudo systemctl start alert-snort
   ```

5. **Verify Installation**:

   ```bash
   # Check service status
   sudo systemctl status alert-snort

   # View Snort alerts in real-time
   sudo journalctl -fu alert-snort
   ```

This configuration sets up Snort as a system service that monitors network traffic and logs alerts for SSH connection attempts. The service automatically restarts if it fails and starts on system boot.

## Step 5: Intrusion Prevention System (IPS) Setup with Fail2ban

1. **Install Required Packages**:

   ```bash
   sudo apt-get update
   sudo apt-get install fail2ban libapache2-mod-security2
   ```

2. **Configure ModSecurity**:
   Create/Update `/etc/modsecurity/modsecurity.conf`:

   ```apache
   SecRuleEngine On
   SecAuditEngine On
   SecAuditLog /var/log/apache2/modsec_audit.log
   SecDefaultAction "phase:2,deny,log,status:403"
   ```

3. **Configure Fail2ban Jail**:
   Create `/etc/fail2ban/jail.local`:

   ```ini
   [DEFAULT]
   bantime = 3600
   findtime = 600
   maxretry = 3

   [sshd]
   enabled = true
   port = ssh
   filter = sshd
   logpath = /var/log/auth.log

   [modsecurity]
   enabled = true
   port = http,https
   filter = modsec
   logpath = /var/log/apache2/modsec_audit.log
   maxretry = 2
   ```

4. **Create ModSecurity Filter for Fail2ban**:
   Create `/etc/fail2ban/filter.d/modsec.conf`:

   ```ini
   [Definition]
   failregex = ^%(__prefix_line)s\[.*?\] \[client <HOST>\] ModSecurity: .*$
   ignoreregex =
   ```

5. **Apply Changes**:

   ```bash
   # Restart Apache to apply ModSecurity changes
   sudo systemctl restart apache2

   # Restart Fail2ban to apply new configuration
   sudo systemctl restart fail2ban
   ```

6. **Verify Configuration**:

   ```bash
   # Check Fail2ban status
   sudo fail2ban-client status

   # Check ModSecurity jail status
   sudo fail2ban-client status modsecurity

   # Check active jails
   sudo fail2ban-client status | grep "Jail list"
   ```

This configuration integrates ModSecurity with Fail2ban to automatically ban IP addresses that trigger ModSecurity rules. The system is set to:

- Ban IPs for 1 hour (3600 seconds)
- Look for violations within a 10-minute window (600 seconds)
- Ban after 3 failed attempts for SSH
- Ban after 2 ModSecurity violations
- Monitor both HTTP and HTTPS traffic

Logs can be monitored in:

- `/var/log/apache2/modsec_audit.log` for ModSecurity events
- `/var/log/fail2ban.log` for Fail2ban actions

## Final Exercises

1. **Unauthorized SSH Connection Alert**:

   ```
   alert tcp !<admin_ip> any -> <server_ip> 22 (msg:"Unauthorized SSH connection attempt"; sid:1000004; rev:1;)
   ```

2. **XMAS Scan Alert**:

   ```
   alert tcp any any -> any any (flags: FPU; msg:"XMAS scan attempt detected"; sid:1000002; rev:1;)
   ```

3. **Sensitive File Access Alert**:

   ```
   alert http any any -> any any (msg:"Access to sensitive file acquisitions.md"; content:"acquisitions.md"; sid:1000005; rev:1;)
   ```

4. **Prevent Access to "About You" Page**:

   ```
   SecRule REQUEST_URI "/about_you" "id:1234,deny,log,msg:'Attempt to access restricted page'"
   ```

5. **DoS Detection and Prevention**:
   - Detect with Snort:
     ```
     alert tcp any any -> any 80 (msg:"Possible DoS attack detected"; threshold:type limit, track by_src, count 50, seconds 10; sid:1000006; rev:1;)
     ```
   - Prevent with iptables:
     ```bash
     sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
     sudo iptables -A INPUT -p tcp --dport 80 -j DROP
     ```
