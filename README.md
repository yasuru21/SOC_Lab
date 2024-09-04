## Part 1: Mapping our SOC Automation Lab

This step is important for mapping out how we want to build/design our lab logically. Understanding how our data will flow is key to making everything work.

![SOC Automation Lab Diagram drawio](https://github.com/user-attachments/assets/028ab5cd-c318-48c4-8d9e-035419788505)

## Part 2: Install Applications and Virtual Machines

### 1. Install Windows 10 Client Machine

- Download and install VirtualBox from [virtualbox.org](http://virtualbox.org)
- Download Windows 10 ISO using the Media Creation Tool
- Create a new VM in VirtualBox:
    - Name: Demo (or your choice)
    - Memory: 4GB RAM
    - CPU: 1 core
    - Hard disk: 50GB
- Install Windows 10 on the VM

### 2. Install Sysmon on Windows 10 VM

- Download Sysmon from the official Microsoft website
- Download Sysmon configuration file (sysmon-config.xml)
- Extract Sysmon files
- Open PowerShell as Administrator
- Navigate to Sysmon directory
- Install Sysmon: `.\sysmon64.exe -i sysmon-config.xml`
- Verify installation through Services or Event Viewer

### 3. Set Up Wazuh Server

- Use a cloud provider (e.g., DigitalOcean)
- Create a Virtual Machine (Droplet if using DigitalOcean):
    - OS: Ubuntu 22.04
    - Plan: Basic with 4GB RAM, 50GB SSD
    - Region: Choose nearest to you
- Set up a firewall: (If you do not create rules for your firewall, SSH is open to the public)
    - Allow SSH access only from your IP
    - Apply firewall to Wazuh droplet
- SSH into the Wazuh server using PuTTY or any other SSH Tool
- Update and upgrade: `apt-get update && apt-get upgrade`
- Install Wazuh using the curl command (refer to Wazuh documentation)
- Note down the admin username and password
- Access Wazuh dashboard via HTTPS://[Wazuh-Server-IP]

### 4. Set Up TheHive Server

- Create another Virtual Machine for TheHive (same specs as Wazuh server)
- SSH into TheHive server
- Install prerequisites:
    - Java
    - Cassandra
    - Elasticsearch
    - TheHive
- Follow TheHive documentation for detailed installation steps

After installation, the next step is to configure Wazuh and TheHive to work together.

## Part 3: Configuring TheHive and Wazuh Server

### 1. Configuring TheHive

### 1.1 Configure Cassandra

- Edit Cassandra's configuration file: `nano /etc/cassandra/cassandra.yaml`
- Change the cluster name (e.g., to "demo")
- Update listen_address and rpc_address to your TheHive server's public IP
- Change the seed_provider address to your TheHive server's public IP
- Save and exit the file
- Stop Cassandra service: `systemctl stop cassandra`
- Remove old Cassandra files: `rm -rf /var/lib/cassandra/*`
- Start Cassandra service: `systemctl start cassandra`
- Verify Cassandra is running: `systemctl status cassandra`

### 1.2 Configure Elasticsearch

- Edit Elasticsearch configuration: `nano /etc/elasticsearch/elasticsearch.yml`
- Set [cluster.name](http://cluster.name) to "thehive"
- Uncomment and set [node.name](http://node.name) to "node-1"
- Set network.host to your TheHive server's public IP
- Uncomment http.port and leave it as 9200
- Uncomment cluster.initial_master_nodes and remove "node-2"
- Save and exit the file
- Start and enable Elasticsearch:
`systemctl start elasticsearch
systemctl enable elasticsearch`
- Verify Elasticsearch is running: `systemctl status elasticsearch`

### 1.3 Configure TheHive

- Change ownership of TheHive directory: `chown -R thehive:thehive /opt/thp`
- Edit TheHive configuration: `nano /etc/thehive/application.conf`
- Update database.hostname and index.hostname to your TheHive server's public IP
- Change [db.name](http://db.name) to match Cassandra's cluster name (e.g., "demo")
- Update application.baseUrl to your TheHive server's public IP
- Save and exit the file
- Start and enable TheHive:
`systemctl start thehive
systemctl enable thehive`
- Verify TheHive is running: `systemctl status thehive`

### 1.4 Troubleshooting TheHive

- If you encounter login issues, check Elasticsearch:
`nano /etc/elasticsearch/jvm.options.d/jvm.options`
- Add the following content to limit Java memory usage:
`-Xms2g
-Xmx2g`
- Save the file and restart Elasticsearch: `systemctl restart elasticsearch`

### 2. Configuring Wazuh

### 2.1 Access Wazuh Dashboard

- Log in to Wazuh dashboard using admin credentials
- If you don't have credentials, on Wazuh server:
`cd /var/ossec
cat wazuh-password.txt`

### 2.2 Add Wazuh Agent to Windows 10 Client

- In Wazuh dashboard, click "Add agent"
- Select Windows as the operating system
- Enter Wazuh server's public IP for "Server address"
- Assign an agent name (optional)
- Copy the provided installation command

### 2.3 Install Wazuh Agent on Windows 10 Client

- Open PowerShell as Administrator on Windows 10 client
- Paste and run the copied installation command
- Start Wazuh service: `net start WazuhSvc`
- Alternatively, start the service through Windows Services

### 2.4 Verify Agent Connection

- Return to Wazuh dashboard
- Check for the new agent in the "Agents" section
- Verify that the agent status changes from "Disconnected" to "Active"

With these steps completed, you have successfully configured TheHive and Wazuh server, and connected a Windows 10 client as a Wazuh agent. The next part will focus on generating telemetry and creating alerts related to Mimikatz usage.

## Part 4: Generate Telemetry from Windows 10 VM and Ingest it into Wazuh

### 1. Configure Wazuh Agent on Windows 10 VM

- Open File Explorer and navigate to C:\Program Files (x86)\ossec-agent
- Locate the ossec.conf file
- Right-click ossec.conf and open with Notepad (run as administrator)
- Scroll down to the <localfile> section
- Add Sysmon log ingestion configuration:

`&lt;localfile&gt;
  &lt;location&gt;Microsoft-Windows-Sysmon/Operational&lt;/location&gt;
  &lt;log_format&gt;eventchannel&lt;/log_format&gt;
&lt;/localfile&gt;`
- Save the file and exit Notepad
- Restart the Wazuh agent service:
`net stop WazuhSvc
net start WazuhSvc`

### 2. Configure Wazuh Manager to Log Everything

- SSH into your Wazuh manager
- Create a backup of the ossec.conf file:
`sudo cp /var/ossec/etc/ossec.conf /home/user/ossec-backup.conf`
- Edit the ossec.conf file:
`sudo nano /var/ossec/etc/ossec.conf`
- Locate the <alerts> section and modify:

`&lt;alerts&gt;
  &lt;log_alert_level&gt;0&lt;/log_alert_level&gt;
  &lt;log_all&gt;yes&lt;/log_all&gt;
  &lt;log_all_json&gt;yes&lt;/log_all_json&gt;
&lt;/alerts&gt;`
- Save and exit the file
- Restart the Wazuh manager:
`sudo systemctl restart wazuh-manager`

### 3. Configure Filebeat to Ingest Archives

- Edit the Filebeat configuration:
`sudo nano /etc/filebeat/filebeat.yml`
- Find the archives section and set enabled to true:

  `archives:
    enabled: true`
- Save and exit the file
- Restart Filebeat:
`sudo systemctl restart filebeat`

### 4. Create a New Index Pattern in Wazuh Dashboard

- Open the Wazuh dashboard in your web browser
- Click on the hamburger menu (top left) and select "Stack Management"
- Click on "Index Patterns" in the left sidebar
- Click "Create index pattern"
- Name the index "wazuh-archives-*"
- Select "@timestamp" as the Time field
- Click "Create index pattern"

### 5. Generate Telemetry Using Mimikatz

- On your Windows 10 VM, disable Windows Defender or exclude the Downloads folder
- Download Mimikatz and extract it to the Downloads folder
- Open an administrative PowerShell and navigate to the Mimikatz folder
- Run Mimikatz:
`.\mimikatz.exe`

### 6. Create a Custom Rule to Detect Mimikatz

- In the Wazuh dashboard, go to Management > Rules
- Click on "Manage rule files" and select "Custom rules"
- Edit the local_rules.xml file
- Add the following rule:

`&lt;rule id="100002" level="15"&gt;
  &lt;field name="win.eventdata.originalFileName"&gt;mimikatz&lt;/field&gt;
  &lt;description&gt;Mimikatz usage detected&lt;/description&gt;
  &lt;mitre&gt;
    &lt;id&gt;T1003&lt;/id&gt;
  &lt;/mitre&gt;
&lt;/rule&gt;`
- Save the file and restart the Wazuh manager

### 7. Verify Telemetry Ingestion and Alert Generation

- In the Wazuh dashboard, go to Discover
- Select the "wazuh-archives-*" index pattern
- Search for "mimikatz" in the search bar
- Verify that Mimikatz events are being ingested
- Go to Security events and check for the custom Mimikatz alert

This completes the process of generating telemetry from the Windows 10 VM, ingesting it into Wazuh, and creating a custom alert for Mimikatz usage. The next part will focus on connecting Shuffle (SOAR) to automate the response to these alerts.

## Part 5: Connecting Shuffle (SOAR) to TheHive and Setting Up Email Notifications

### 1. Set Up Shuffle Workflow

- Create a new workflow in Shuffle
- Add a webhook as the trigger for the workflow
- Copy the webhook URL for later use in Wazuh configuration

### 2. Configure Wazuh to Send Alerts to Shuffle

- Edit the Wazuh manager's ossec.conf file
- Add an integration tag for Shuffle
- Include the webhook URL and specify the rule ID for Mimikatz detection
- Restart the Wazuh manager service

### 3. Set Up VirusTotal Integration in Shuffle

- Add VirusTotal app to the workflow
- Configure VirusTotal with API key
- Set up action to check file hash reputation

### 4. Configure TheHive Integration

- Create a new organization and users in TheHive
- Generate an API key for Shuffle integration
- Add TheHive app to the Shuffle workflow
- Configure TheHive app with API key and server URL
- Set up action to create an alert in TheHive

### 5. Set Up Email Notification

- Add email app to the Shuffle workflow
- Configure email settings (recipient, subject, body)
- Include relevant information from the Wazuh alert and VirusTotal results

### 6. Test the Workflow

- Generate a test Mimikatz alert in Wazuh
- Verify that Shuffle receives the alert
- Check VirusTotal reputation lookup
- Confirm alert creation in TheHive
- Verify email notification receipt

This guide outlines the process of connecting Shuffle (SOAR) to TheHive and setting up email notifications for Mimikatz detection alerts. Follow these steps to create a comprehensive automated workflow for handling security alerts.

Final Result Workflow:

1. Mimikatz Alert sent to Shuffle
2. Shuffle receives Mimikatz alert 
    1. Extract SHA256 Hash from file
3. Check Reputation Score with VirusTotal
4. Send details to TheHive to create alert
5. Send email to SOC Analyst to begin investigation

Final Thoughts:
This lab provides a comprehensive exploration of essential skills for SOC and cybersecurity analysts, particularly focusing on alert handling and SOAR automation. Mastery of these skills can significantly streamline analyst workflows. Wazuh, Shuffle, and TheHive are excellent resources for hands-on practice, and this lab effectively guides users through the intricacies of these tools, making it a valuable learning experience.
