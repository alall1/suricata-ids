# I. Introduction
To gain hands-on experience with networks, cyberattacks, and intrusion detection systems(IDS), I created a virtual environment to simulate attacks on a vulnerable web application. To detect the attacks, I wrote custom rules for specific attacks in Suricata and used Evebox for visualizing alerts. This project has improved my skills in Linux, SQL, networking, 

The tools I used are:
- VirtualBox: a hypervisor to run the virtual machines(VMs) and set up an inline routing system
- Debian & Kali Linux: the latest version of Debian operating systems for the victim and the IDS, and Kali for the attacker
- Apache, MySQL(MariaDB), & PHP: to create and run the vulnerable web app, completing the LAMP stack
- Suricata & Evebox: IDS and a web visualization of alerts
- Nmap, SQLmap, hydra, & hping3: Attack tools built-in to Kali used in this project

**Architecture:**
<Diagram>

Host-only networks were the best way to isolate the lab environment from the Internet, so I used two of them(one for the attacker, one for the victim) to create an inline routing network topology. In the first subnet, the attacker sends packets to one of the IDS's interfaces, also on that same network. The IDS then forwards the packets through its second interface to the victim, on the second subnet. I used inline routing to better simulate how an actual IDS would work, placed at a gateway.

Subnet 1: 10.10.0.0/24, Traffic Flow: Attacker <-> IDS

Subnet 2: 10.20.0.0/24, Traffic Flow: Victim <-> IDS
# II. Lab Setup
| VM | OS | Role | Network Mode | IP Address | RAM | CPU |
|---|---|---|---|---|---|---|
| Attacker | Kali | Offensive | Host-Only | 10.10.0.2 | 4GB | 2 cores |
| Victim | Debian 13 | Vulnerable Web App | Host-Only | 10.20.0.2 | 2GB | 2 cores |
| IDS | Debian 13 | Inline Routing & IDS | Host-Only & Host-Only | 10.10.0.10 & 10.20.0.10 | 2GB | 2 cores |
  
**Vulnerable Web App Setup:**  
First, install Apache, MySQL, PHP, and all the associated libraries. Next, create the intentionally vulnerable database, using plaintext to store usernames and passwords. Finally, use insecure practices in the PHP file, like not sanitizing inputs and directly using parameters in database queries.

