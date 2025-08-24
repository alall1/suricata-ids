# I. Introduction
To gain hands-on experience with networks, cyberattacks, and intrusion detection systems(IDS), I created a virtual environment to simulate attacks on a vulnerable web application. To detect the attacks, I wrote custom rules for specific attacks in Suricata and used Evebox for visualizing alerts. This project has improved my skills in network architecture, network security, intrusion detection, Linux, SQL, and PHP, as well as using virtual machines.

The tools I used are:
- VirtualBox: a hypervisor to run the virtual machines(VMs) and set up an inline routing system
- Debian & Kali Linux: the latest version of Debian operating systems for the victim and the IDS, and Kali for the attacker
- Apache, MySQL(MariaDB), & PHP: to create and run the vulnerable web app, completing the LAMP stack
- Suricata & Evebox: IDS and a web visualization of alerts
- Nmap, SQLmap, hydra, & hping3: Attack tools built-in to Kali used in this project

**Architecture:**

Host-only networks were the best way to isolate the lab environment from the Internet, so I used two of them(one for the attacker, one for the victim) to create an inline routing network topology. In the first subnet, the attacker sends packets to one of the IDS's interfaces, also on that same network. The IDS then forwards the packets through its second interface to the victim, on the second subnet. I used inline routing to better simulate how an actual IDS would work, placed at a gateway.

![Inline Routing Diagram](images/inline-routing-diagram.png)

<p align="center">Subnet 1: 10.10.0.0/24, Traffic Flow: Attacker <-> IDS, Subnet 2: 10.20.0.0/24, Traffic Flow: Victim <-> IDS</p>

The attacker at 10.10.0.2 uses the gateway 10.10.0.10, the IDS VM, to send packets to the victim at 10.20.0.2. Similarly, the victim at 10.20.0.2 uses the gateway 10.20.0.10, again the IDS VM, to send packets back to the attacker at 10.10.0.2. This way, Suricata captures all the packets being sent back and forth, and the IDS VM doesn't have to be set to promiscuous mode.
# II. Lab Setup
| VM | OS | Role | Network Mode | IP Address | RAM | CPU |
|---|---|---|---|---|---|---|
| Attacker | Kali | Offensive | Host-Only | 10.10.0.2 | 4GB | 2 cores |
| Victim | Debian 13 | Vulnerable Web App | Host-Only | 10.20.0.2 | 2GB | 2 cores |
| IDS | Debian 13 | Inline Routing & IDS | Host-Only & Host-Only | 10.10.0.10 & 10.20.0.10 | 2GB | 2 cores |

**Inline Routing Setup:** 
First, I started with setting up the inline routing network, as inline routing is the foundation of this project. The first step is to navigate to the network manager in VirtualBox and add two host-only networks. Inline routing can also be done on a single network, but I decided to make two separate networks so the distinction between the attacker and the victim would be clear. 

![Network Manager](images/network-manager.png)
<p align="center">VirtualBox Network Manager Host-only Networks</p>

Next, go to each VM's network settings and add the appropriate host-only adapters: vboxnetA for the attacker, vboxnetB for the victim, and two adapters for vboxnetA and vboxnetB on the IDS VM. To verify, run each VM and check the networks with "ip a" on the command line. Each one should have an IP in their specific subnets, and for the IDS VM it should have two networks(eth0 and eth1 or enp0s8 and enp0s9) with IPs in both subnets. I would recommend adding a static IP for the IDS VM, as well as the attacker and victim. You can do this by modifying /etc/network/interfaces, which you will need to add these changes to enable IP forwarding:

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/interfaces-attacker.png" alt="attacker/etc/network/interfaces">
</p>
<p align="center">Attacker /etc/network/interfaces</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/interfaces-victim.png" alt="victim /etc/network/interfaces">
</p>
<p align="center">Victim /etc/network/interfaces</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/interfaces-ids.png" alt="ids /etc/network/interfaces">
</p>
<p align="center">IDS /etc/network/interfaces</p>

Finally, edit /etc/nftables.conf and /etc/sysctl.conf as specified [here](docs/setup). From the attacker VM, ping the IP address of the victim VM and vice versa to make sure the IP forwarding works. From the IDS VM, use tcpdump on one of the networks to view the ICMP traffic going back and forth between the attacker and the victim. 

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/ping-attacker.png" alt="attacker pings">
</p>
<p align="center">Attacker pinging victim IP</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/ping-victim.png" alt="victim pings">
</p>
<p align="center">Victim pinging attacker IP</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/ping-idstcpdump.png" alt="ids tcpdump">
</p>
<p align="center">tcpdump from both enp0s8 and enp0s9 on IDS VM</p>
  
**Vulnerable Web App Setup:**

First, install Apache, MySQL, PHP, and all the associated libraries. Next, create the intentionally vulnerable database, using plaintext to store usernames and passwords. Finally, use insecure practices in the PHP file, like not sanitizing inputs and directly using parameters in database queries.

The installation of Apache, MySQL, and PHP, and creating the intentionally vulnerable database in MySQL is documented [here](docs/setup). The insecure PHP file can be found [here](docs/login.php). The database and website should look like this:

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/web-app-database.png" alt="user database">
</p>
<p align="center">Vulnsite database, stored in plaintext</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/victim-site.png" alt="vulnerable site">
</p>
<p align="center">Vulnerable login page</p>

Test the login page by inputting the valid login credentials and invalid login credentials, and try to use SQL injection like "' OR '1'='1'" and "admin' OR '1'='1' --". Make sure the attacker VM can access the website either through a browser or through using curl "login page url".

**Suricata and EveBox Setup:**

The final step for setting up the lab is installing Suricata and EveBox. After installation, configure /etc/suricata/suricata.yaml and /etc/evebox/evebox.yaml as shown [here](docs/setup). Then, create a custom.rules file in /etc/suricata/rules with the rules given [here](docs/rules), as well as any other attacks that should be detected. Ensure that Suricata writes alerts to eve.json in suricata.yaml and that EveBox is pointing towards eve.json in evebox.yaml. To test the functionality of Suricata, run a basic nmap scan like "nmap -F 'victim IP'", and check /var/log/suricata/fast.log for quick alerts, and /var/log/suricata/eve.json to see if Suricata is logging alerts into eve.json. 

To run Suricata in the foreground, use the CLI command "sudo suricata -c /etc/suricata/suricata.yaml --af-packet". In this project, I ran Suricata in the foreground, so I could control when it was active, but realistically it would always be active in the background. To run EveBox for analysis of the alerts currently in eve.json, use the CLI command "evebox oneshot /var/log/suricata/eve.json". Again, EveBox would realistically be constantly ingesting alerts from eve.json to be viewed at any time, but I found it easier to use oneshot for this project.

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/IDS-suricata-running.png" alt="suricata running">
</p>
<p align="center">Running Suricata in the foreground</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/attacker-test-nmap.png" alt="test nmap scan">
</p>
<p align="center">Running a quick test nmap scan from the attacker</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/IDS-test-nmap.png" alt="fast.log and eve.json">
</p>
<p align="center">Logs in fast.log and eve.json</p>

<p align="center">
  <img src="https://github.com/alall1/suricata-ids/blob/main/images/IDS-evebox-test-nmap.png" alt="evebox nmap test">
</p>
<p align="center">Viewing the test nmap scan in EveBox</p>

With this, setup is complete. Inline routing has been configured, the intentionally vulnerable web application is running, and EveBox is ingesting alerts generated by Suricata to be viewed in a web browser.

# III. Attacks and Alerts

