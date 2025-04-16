

**Question 1:**  
Match the type of ASA ACLs to the description. (Not all options are used.)  
*Place the options in the following order:*  
**Choices:**  
A. extended access lists – used to specify source and destination addresses and protocol, ports, or the ICMP type  
B. webtype access lists – used to support filtering for clientless SSL VPN  
C. standard access lists – used to identify the destination IP addresses only  
D. EtherType access lists – used only if the security appliance is running in transparent mode

---

**Question 2:**  
Which statement describes a difference between the Cisco ASA IOS CLI feature and the router IOS CLI feature?  
**Choices:**  
A. ASA uses the ? command whereas a router uses the help command to receive help on a brief description and the syntax of a command.  
B. To use a show command in a general configuration mode, ASA can use the command directly whereas a router will need to enter the do command before issuing the show command.  
C. To complete a partially typed command, ASA uses the Ctrl+Tab key combination whereas a router uses the Tab key.  
D. To indicate the CLI EXEC mode, ASA uses the % symbol whereas a router uses the # symbol.

---

**Question 3:**  
Refer to the exhibit. A network administrator is configuring AAA implementation on an ASA device. What does the option link3 indicate?  
**Choices:**  
A. the network name where the AAA server resides  
B. the specific AAA server name  
C. the sequence of servers in the AAA server group  
D. the interface name

---

**Question 4:**  
What provides both secure segmentation and threat defense in a Secure Data Center solution?  
**Choices:**  
A. Cisco Security Manager software  
B. AAA server  
C. Adaptive Security Appliance  
D. intrusion prevention system

---

**Question 5:**  
What are the three core components of the Cisco Secure Data Center solution? (Choose three.)  
**Choices:**  
A. mesh network  
B. secure segmentation  
C. visibility  
D. threat defense  
E. servers  
F. infrastructure

---

**Question 6:**  
What are three characteristics of ASA transparent mode? (Choose three.)  
**Choices:**  
A. This mode does not support VPNs, QoS, or DHCP Relay.  
B. It is the traditional firewall deployment mode.  
C. This mode is referred to as a “bump in the wire.”  
D. NAT can be implemented between connected networks.  
E. In this mode the ASA is invisible to an attacker.  
F. The interfaces of the ASA separate Layer 3 networks and require IP addresses in different subnets.

---

**Question 7:**  
What is needed to allow specific traffic that is sourced on the outside network of an ASA firewall to reach an internal network?  
**Choices:**  
A. ACL  
B. NAT  
C. dynamic routing protocols  
D. outside security zone level 0

---

**Question 8:**  
What will be the result of failed login attempts if the following command is entered into a router?  
```
login block-for 150 attempts 4 within 90
```  
**Choices:**  
A. All login attempts will be blocked for 150 seconds if there are 4 failed attempts within 90 seconds.  
B. All login attempts will be blocked for 90 seconds if there are 4 failed attempts within 150 seconds.  
C. All login attempts will be blocked for 1.5 hours if there are 4 failed attempts within 150 seconds.  
D. All login attempts will be blocked for 4 hours if there are 90 failed attempts within 150 seconds.

---

**Question 9:**  
Which two tasks are associated with router hardening? (Choose two.)  
**Choices:**  
A. placing the router in a secure room  
B. disabling unused ports and interfaces  
C. installing the maximum amount of memory possible  
D. securing administrative access  
E. using uninterruptible power supplies

---

**Question 10:**  
Which threat protection capability is provided by Cisco ESA?  
**Choices:**  
A. web filtering  
B. cloud access security  
C. spam protection  
D. Layer 4 traffic monitoring

---

**Question 11:**  
What are two security measures used to protect endpoints in the borderless network? (Choose two.)  
**Choices:**  
A. denylisting  
B. Snort IPS  
C. DLP  
D. DMZ  
E. rootkit

---

**Question 12:**  
Which three types of traffic are allowed when the authentication port-control auto command has been issued and the client has not yet been authenticated? (Choose three.)  
**Choices:**  
A. CDP  
B. 802.1Q  
C. IPsec  
D. TACACS+  
E. STP  
F. EAPOL

---

**Question 13:**  
Which statement describes a characteristic of the IKE protocol?  
**Choices:**  
A. It uses UDP port 500 to exchange IKE information between the security gateways.  
B. IKE Phase 1 can be implemented in three different modes: main, aggressive, or quick.  
C. It allows for the transmission of keys directly across a network.  
D. The purpose of IKE Phase 2 is to negotiate a security association between two IKE peers.

---

**Question 14:**  
Which action do IPsec peers take during the IKE Phase 2 exchange?  
**Choices:**  
A. exchange of DH keys  
B. negotiation of IPsec policy  
C. negotiation of IKE policy sets  
D. verification of peer identity

---

**Question 15:**  
What are two hashing algorithms used with IPsec AH to guarantee authenticity? (Choose two.)  
**Choices:**  
A. SHA  
B. RSA  
C. DH  
D. MD5  
E. AES

---

**Question 16:**  
Which command raises the privilege level of the ping command to 7?  
**Choices:**  
A. user exec ping level 7  
B. authorization exec ping level 7  
C. accounting exec level 7 ping  
D. privilege exec level 7 ping

---

**Question 17:**  
What is a characteristic of a role-based CLI view of router configuration?  
**Choices:**  
A. A CLI view has a command hierarchy, with higher and lower views.  
B. When a superview is deleted, the associated CLI views are deleted.  
C. A single CLI view can be shared within multiple superviews.  
D. Only a superview user can configure a new view and add or remove commands from the existing views.

---

**Question 18:**  
What is a limitation to using OOB management on a large enterprise network?  
**Choices:**  
A. Production traffic shares the network with management traffic.  
B. Terminal servers can have direct console connections to user devices needing management.  
C. OOB management requires the creation of VPNs.  
D. All devices appear to be attached to a single management network.

---

**Question 19:**  
Refer to the exhibit. A corporate network is using NTP to synchronize the time across devices. What can be determined from the displayed output?  
**Choices:**  
A. Router03 is a stratum 2 device that can provide NTP service to other devices in the network.  
B. The time on Router03 may not be reliable because it is offset by more than 7 seconds to the time server.  
C. The interface on Router03 that connects to the time server has the IPv4 address 209.165.200.225.  
D. Router03 time is synchronized to a stratum 2 time server.

---

**Question 20:**  
Refer to the exhibit. Which two conclusions can be drawn from the syslog message that was generated by the router? (Choose two.)  
**Choices:**  
A. This message resulted from an unusual error requiring reconfiguration of the interface.  
B. This message indicates that service timestamps have been configured.  
C. This message indicates that the interface changed state five times.  
D. This message is a level 5 notification message.  
E. This message indicates that the interface should be replaced.

---

**Question 21:**  
Which two types of hackers are typically classified as grey hat hackers? (Choose two.)  
**Choices:**  
A. hacktivists  
B. cyber criminals  
C. vulnerability brokers  
D. script kiddies  
E. state-sponsored hackers

---

**Question 22:**  
When describing malware, what is a difference between a virus and a worm?  
**Choices:**  
A. A virus focuses on gaining privileged access to a device, whereas a worm does not.  
B. A virus replicates itself by attaching to another file, whereas a worm can replicate itself independently.  
C. A virus can be used to launch a DoS attack (but not a DDoS), but a worm can be used to launch both DoS and DDoS attacks.  
D. A virus can be used to deliver advertisements without user consent, whereas a worm cannot.

---

**Question 23:**  
Which type of packet is unable to be filtered by an outbound ACL?  
**Choices:**  
A. multicast packet  
B. ICMP packet  
C. broadcast packet  
D. router-generated packet

---

**Question 24:**  
Consider the access list command applied outbound on a router serial interface:  
```
access-list 100 deny icmp 192.168.10.0 0.0.0.255 any echo reply
```  
What is the effect of applying this access list command?  
**Choices:**  
A. The only traffic denied is echo-replies sourced from the 192.168.10.0/24 network. All other traffic are allowed.  
B. The only traffic denied is ICMP-based traffic. All other traffic are allowed.  
C. No traffic will be allowed outbound on the serial interface.  
D. Users on the 192.168.10.0/24 network are not allowed to transmit traffic to any other destination.

---

**Question 25:**  
Which command is used to activate an IPv6 ACL named ENG_ACL on an interface so that the router filters traffic prior to accessing the routing table?  
**Choices:**  
A. ipv6 access-class ENG_ACL in  
B. ipv6 traffic-filter ENG_ACL out  
C. ipv6 traffic-filter ENG_ACL in  
D. ipv6 access-class ENG_ACL out

---

**Question 26:**  
What technology has a function of using trusted third-party protocols to issue credentials that are accepted as an authoritative identity?  
**Choices:**  
A. digital signatures  
B. hashing algorithms  
C. PKI certificates  
D. symmetric keys

---

**Question 27:**  
What are two methods to maintain certificate revocation status? (Choose two.)  
**Choices:**  
A. subordinate CA  
B. OCSP  
C. DNS  
D. LDAP  
E. CRL

---

**Question 28:**  
Which protocol is an IETF standard that defines the PKI digital certificate format?  
**Choices:**  
A. SSL/TLS  
B. X.500  
C. LDAP  
D. X.509

---

**Question 29:**  
A network administrator is configuring DAI on a switch. Which command should be used on the uplink interface that connects to a router?  
**Choices:**  
A. ip arp inspection trust  
B. ip dhcp snooping  
C. ip arp inspection vlan  
D. spanning-tree portfast

---

**Question 30:**  
What is the best way to prevent a VLAN hopping attack?  
**Choices:**  
A. Disable trunk negotiation for trunk ports and statically set nontrunk ports as access ports.  
B. Disable STP on all nontrunk ports.  
C. Use VLAN 1 as the native VLAN on trunk ports.  
D. Use ISL encapsulation on all trunk links.

---

**Question 31:**  
What would be the primary reason an attacker would launch a MAC address overflow attack?  
**Choices:**  
A. so that the switch stops forwarding traffic  
B. so that legitimate hosts cannot obtain a MAC address  
C. so that the attacker can see frames that are destined for other hosts  
D. so that the attacker can execute arbitrary code on the switch

---

**Question 32:**  
What is the main difference between the implementation of IDS and IPS devices?  
**Choices:**  
A. An IDS can negatively impact the packet flow, whereas an IPS cannot.  
B. An IDS needs to be deployed together with a firewall device, whereas an IPS can replace a firewall.  
C. An IDS would allow malicious traffic to pass before it is addressed, whereas an IPS stops it immediately.  
D. An IDS uses signature-based technology to detect malicious packets, whereas an IPS uses profile-based technology.

---

**Question 33:**  
Which attack is defined as an attempt to exploit software vulnerabilities that are unknown or undisclosed by the vendor?  
**Choices:**  
A. zero-day  
B. Trojan horse  
C. brute-force  
D. man-in-the-middle

---

**Question 34:**  
Match the network monitoring technology with the description.  
*Place the options in the following order:*  
**Choices:**  
A. passively monitors network traffic – IDS  
B. uses VLANs to monitor traffic on remote switches – RSPAN  
C. a passive traffic splitting device implemented inline between a device of interest and the network – TAP  
D. can perform a packet drop to stop the trigger packets – IPS

---

**Question 35:**  
What are the three signature levels provided by Snort IPS on the 4000 Series ISR? (Choose three.)  
**Choices:**  
A. security  
B. drop  
C. reject  
D. connectivity  
E. inspect  
F. balanced

---

**Question 36:**  
What are three attributes of IPS signatures? (Choose three.)  
**Choices:**  
A. action  
B. length  
C. trigger  
D. type  
E. depth  
F. function

---

**Question 37:**  
Match each IPS signature trigger category with the description.  
*Options:*  
A. pattern-based detection – simplest triggering mechanism which searches for a specific and pre-defined atomic or composite pattern  
B. anomaly-based detection – involves first defining a profile of what is considered normal network or host activity  
C. honey pot-based detection – uses a decoy server to divert attacks away from production devices

---

**Question 38:**  
Which two features are included by both TACACS+ and RADIUS protocols? (Choose two.)  
**Choices:**  
A. SIP support  
B. password encryption  
C. 802.1X support  
D. separate authentication and authorization processes  
E. utilization of transport layer protocols

---

**Question 39:**  
What function is provided by the RADIUS protocol?  
**Choices:**  
A. RADIUS provides encryption of the complete packet during transfer.  
B. RADIUS provides separate AAA services.  
C. RADIUS provides separate ports for authorization and accounting.  
D. RADIUS provides secure communication using TCP port 49.

---

**Question 40:**  
What are three characteristics of the RADIUS protocol? (Choose three.)  
**Choices:**  
A. utilizes TCP port 49  
B. uses UDP ports for authentication and accounting  
C. supports 802.1X and SIP  
D. separates the authentication and authorization processes  
E. encrypts the entire body of the packet  
F. is an open RFC standard AAA protocol

---

**Question 41:**  
Which zone-based policy firewall zone is system-defined and applies to traffic destined for the router or originating from the router?  
**Choices:**  
A. local zone  
B. inside zone  
C. self zone  
D. system zone  
E. outside zone

---

**Question 42:**  
What are two benefits of using a ZPF rather than a Classic Firewall? (Choose two.)  
**Choices:**  
A. ZPF allows interfaces to be placed into zones for IP inspection.  
B. The ZPF is not dependent on ACLs.  
C. Multiple inspection actions are used with ZPF.  
D. ZPF policies are easy to read and troubleshoot.  
E. With ZPF, the router will allow packets unless they are explicitly blocked.

---

**Question 43:**  
Place the steps for configuring zone-based policy (ZPF) firewalls in order from first to last. (Not all options are used.)  
*Place the options in the following order:*  
**Choices:**  
A. Create zones.  
B. Define traffic classes.  
C. Create policies.  
D. Assign zones to interfaces.  
E. Apply policies.

---

**Question 44:**  
How does a firewall handle traffic when it is originating from the private network and traveling to the DMZ network?  
**Choices:**  
A. The traffic is selectively denied based on service requirements.  
B. The traffic is usually permitted with little or no restrictions.  
C. The traffic is selectively permitted and inspected.  
D. The traffic is usually blocked.

---

**Question 45:**  
Which two protocols generate connection information within a state table and are supported for stateful filtering? (Choose two.)  
**Choices:**  
A. ICMP  
B. UDP  
C. DHCP  
D. TCP  
E. HTTP

---

**Question 46:**  
Which type of firewall is supported by most routers and is the easiest to implement?  
**Choices:**  
A. next generation firewall  
B. stateless firewall  
C. stateful firewall  
D. proxy firewall

---

**Question 47:**  
What network testing tool would an administrator use to assess and validate system configurations against security policies and compliance standards?  
**Choices:**  
A. Tripwire  
B. L0phtcrack  
C. Nessus  
D. Metasploit

---

**Question 48:**  
What type of network security test can detect and report changes made to network systems?  
**Choices:**  
A. vulnerability scanning  
B. network scanning  
C. integrity checking  
D. penetration testing

---

**Question 49:**  
What network security testing tool has the ability to provide details on the source of suspicious network activity?  
**Choices:**  
A. SIEM  
B. SuperScan  
C. Zenmap  
D. Tripwire

---

**Question 50:**  
How do modern cryptographers defend against brute-force attacks?  
**Choices:**  
A. Use statistical analysis to eliminate the most common encryption keys.  
B. Use a keyspace large enough that it takes too much money and too much time to conduct a successful attack.  
C. Use an algorithm that requires the attacker to have both ciphertext and plaintext to conduct a successful attack.  
D. Use frequency analysis to ensure that the most popular letters used in the language are not used in the cipher message.

---

**Question 51:**  
How does a Caesar cipher work on a message?  
**Choices:**  
A. Letters of the message are replaced by another letter that is a set number of places away in the alphabet.  
B. Letters of the message are rearranged randomly.  
C. Letters of the message are rearranged based on a predetermined pattern.  
D. Words of the message are substituted based on a predetermined pattern.

---

**Question 52:**  
What is the main factor that ensures the security of encryption of modern algorithms?  
**Choices:**  
A. complexity of the hashing algorithm  
B. the use of 3DES over AES  
C. secrecy of the keys  
D. secrecy of the algorithm

---

**Question 53:**  
What is the next step in the establishment of an IPsec VPN after IKE Phase 1 is complete?  
**Choices:**  
A. negotiation of the ISAKMP policy  
B. negotiation of the IPsec SA policy  
C. detection of interesting traffic  
D. authentication of peers

---

**Question 54:**  
Refer to the exhibit. What algorithm will be used for providing confidentiality?  
**Choices:**  
A. RSA  
B. Diffie-Hellman  
C. DES  
D. AES

---

**Question 55:**  
After issuing a `show run` command, an analyst notices the following command in the configuration:  
```
crypto ipsec transform-set MYSET esp-aes 256 esp-md5-hmac
```  
What is the purpose of this command?  
**Choices:**  
A. It establishes the set of encryption and hashing algorithms used to secure the data sent through an IPsec tunnel.  
B. It defines the default ISAKMP policy list used to establish the IKE Phase 1 tunnel.  
C. It establishes the criteria to force the IKE Phase 1 negotiations to begin.  
D. It indicates that IKE will be used to establish the IPsec tunnel for protecting the traffic.

---

**Question 56:**  
Which algorithm can ensure data integrity?  
**Choices:**  
A. RSA  
B. AES  
C. MD5  
D. PKI

---

**Question 57:**  
A company implements a security policy that ensures that a file sent from the headquarters office to the branch office can only be opened with a predetermined code. This code is changed every day. Which two algorithms can be used to achieve this task? (Choose two.)  
**Choices:**  
A. HMAC  
B. MD5  
C. 3DES  
D. SHA-1  
E. AES

---

**Question 58:**  
A network technician has been asked to design a virtual private network between two branch routers. Which type of cryptographic key should be used in this scenario?  
**Choices:**  
A. hash key  
B. symmetric key  
C. asymmetric key  
D. digital signature

---

**Question 59:**  
Which two options can limit the information discovered from port scanning? (Choose two.)  
**Choices:**  
A. intrusion prevention system  
B. firewall  
C. authentication  
D. passwords  
E. encryption

---

**Question 60:**  
An administrator discovers that a user is accessing a newly established website that may be detrimental to company security. What action should the administrator take first in terms of the security policy?  
**Choices:**  
A. Ask the user to stop immediately and inform the user that this constitutes grounds for dismissal.  
B. Create a firewall rule blocking the respective website.  
C. Revise the AUP immediately and get all users to sign the updated AUP.  
D. Immediately suspend the network privileges of the user.

---

**Question 61:**  
If AAA is already enabled, which three CLI steps are required to configure a router with a specific view? (Choose three.)  
**Choices:**  
A. Create a superview using the `parser view view-name` command.  
B. Associate the view with the root view.  
C. Assign users who can use the view.  
D. Create a view using the `parser view` command.  
E. Assign a secret password to the view.  
F. Assign commands to the view.

---

**Question 62:**  
Refer to the exhibit. A network administrator configures a named ACL on the router. Why is there no output displayed when the show command is issued?  
**Choices:**  
A. The ACL is not activated.  
B. The ACL name is case sensitive.  
C. The ACL has not been applied to an interface.  
D. No packets have matched the ACL statements yet.

---

**Question 63:**  
ACLs are used primarily to filter traffic. What are two additional uses of ACLs? (Choose two.)  
**Choices:**  
A. specifying internal hosts for NAT  
B. identifying traffic for QoS  
C. specifying source addresses for authentication  
D. reorganizing traffic into VLANs  
E. filtering VTP packets

---

**Question 64:**  
What two features are added in SNMPv3 to address the weaknesses of previous versions of SNMP? (Choose two.)  
**Choices:**  
A. authentication  
B. authorization with community string priority  
C. bulk MIB objects retrieval  
D. ACL management filtering  
E. encryption

---

**Question 65:**  
What network testing tool is used for password auditing and recovery?  
**Choices:**  
A. Nessus  
B. Metasploit  
C. L0phtcrack  
D. SuperScan

---

**Question 66:**  
Which type of firewall makes use of a server to connect to destination devices on behalf of clients?  
**Choices:**  
A. packet filtering firewall  
B. proxy firewall  
C. stateless firewall  
D. stateful firewall

---

**Question 67:**  
Refer to the exhibit. What will be displayed in the output of the `show running-config object` command after the exhibited configuration commands are entered on an ASA 5506-X?  
**Choices:**  
A. host 192.168.1.4  
B. range 192.168.1.10 192.168.1.20  
C. host 192.168.1.3, host 192.168.1.4, and range 192.168.1.10 192.168.1.20  
D. host 192.168.1.3  
E. host 192.168.1.3 and host 192.168.1.4  
F. host 192.168.1.4 and range 192.168.1.10 192.168.1.20

---

**Question 68:**  
Refer to the exhibit. According to the command output, which three statements are true about the DHCP options entered on the ASA? (Choose three.)  
**Choices:**  
A. The `dhcpd address [start-of-pool]-[end-of-pool] inside` command was issued to enable the DHCP server.  
B. The `dhcpd address [start-of-pool]-[end-of-pool] inside` command was issued to enable the DHCP client.  
C. The `dhcpd enable inside` command was issued to enable the DHCP server.  
D. The `dhcpd auto-config outside` command was issued to enable the DHCP client.  
E. The `dhcpd auto-config outside` command was issued to enable the DHCP server.  
F. The `dhcpd enable inside` command was issued to enable the DHCP client.

---

**Question 69:**  
Which two statements describe the characteristics of symmetric algorithms? (Choose two.)  
**Choices:**  
A. They are commonly used with VPN traffic.  
B. They use a pair of a public key and a private key.  
C. They are commonly implemented in the SSL and SSH protocols.  
D. They provide confidentiality, integrity, and availability.  
E. They are referred to as a pre-shared key or secret key.

---

**Question 70:**  
A web server administrator is configuring access settings to require users to authenticate first before accessing certain web pages. Which requirement of information security is addressed through the configuration?  
**Choices:**  
A. availability  
B. integrity  
C. scalability  
D. confidentiality

---

**Question 71:**  
The use of 3DES within the IPsec framework is an example of which of the five IPsec building blocks?  
**Choices:**  
A. authentication  
B. nonrepudiation  
C. integrity  
D. Diffie-Hellman  
E. confidentiality

---

**Question 72:**  
What function is provided by Snort as part of the Security Onion?  
**Choices:**  
A. to generate network intrusion alerts by the use of rules and signatures  
B. to normalize logs from various NSM data logs so they can be represented, stored, and accessed through a common schema  
C. to display full-packet captures for analysis  
D. to view pcap transcripts generated by intrusion detection tools

---

**Question 73:**  
What are two drawbacks to using HIPS? (Choose two.)  
**Choices:**  
A. With HIPS, the success or failure of an attack cannot be readily determined.  
B. With HIPS, the network administrator must verify support for all the different operating systems used in the network.  
C. HIPS has difficulty constructing an accurate network picture or coordinating events that occur across the entire network.  
D. If the network traffic stream is encrypted, HIPS is unable to access unencrypted forms of the traffic.  
E. HIPS installations are vulnerable to fragmentation attacks or variable TTL attacks.

---

**Question 74:**  
In an AAA-enabled network, a user issues the `configure terminal` command from the privileged executive mode of operation. What AAA function is at work if this command is rejected?  
**Choices:**  
A. authorization  
B. authentication  
C. auditing  
D. accounting

---

**Question 75:**  
A company has a file server that shares a folder named Public. The network security policy specifies that the Public folder is assigned Read-Only rights to anyone who can log into the server while the Edit rights are assigned only to the network admin group. Which component is addressed in the AAA network service framework?  
**Choices:**  
A. automation  
B. accounting  
C. authentication  
D. authorization

---

**Question 76:**  
What is a characteristic of a DMZ zone?  
**Choices:**  
A. Traffic originating from the inside network going to the DMZ network is not permitted.  
B. Traffic originating from the outside network going to the DMZ network is selectively permitted.  
C. Traffic originating from the DMZ network going to the inside network is permitted.  
D. Traffic originating from the inside network going to the DMZ network is selectively permitted.

---

**Question 77:**  
Which measure can a security analyst take to perform effective security monitoring against network traffic encrypted by SSL technology?  
**Choices:**  
A. Use a Syslog server to capture network traffic.  
B. Deploy a Cisco SSL Appliance.  
C. Require remote access connections through IPsec VPN.  
D. Deploy a Cisco ASA.

---

**Question 78:**  
Refer to the exhibit. Port security has been configured on the Fa 0/12 interface of switch S1. What action will occur when PC1 is attached to switch S1 with the applied configuration?  
**Choices:**  
A. Frames from PC1 will be forwarded since the switchport port-security violation command is missing.  
B. Frames from PC1 will be forwarded to its destination, and a log entry will be created.  
C. Frames from PC1 will be forwarded to its destination, but a log entry will not be created.  
D. Frames from PC1 will cause the interface to shut down immediately, and a log entry will be made.  
E. Frames from PC1 will be dropped, and there will be no log of the violation.  
F. Frames from PC1 will be dropped, and a log message will be created.

---

**Question 79:**  
What security countermeasure is effective for preventing CAM table overflow attacks?  
**Choices:**  
A. DHCP snooping  
B. Dynamic ARP Inspection  
C. IP source guard  
D. port security

---

**Question 80:**  
What are two examples of DoS attacks? (Choose two.)  
**Choices:**  
A. port scanning  
B. SQL injection  
C. ping of death  
D. phishing  
E. buffer overflow

---

**Question 81:**  
Which method is used to identify interesting traffic needed to create an IKE phase 1 tunnel?  
**Choices:**  
A. transform sets  
B. a permit access list entry  
C. hashing algorithms  
D. a security association

---

**Question 82:**  
When the CLI is used to configure an ISR for a site-to-site VPN connection, which two items must be specified to enable a crypto map policy? (Choose two.)  
**Choices:**  
A. the hash  
B. the peer  
C. encryption  
D. the ISAKMP policy  
E. a valid access list  
F. IP addresses on all active interfaces  
G. the IKE Phase 1 policy

---

**Question 83:**  
How does a firewall handle traffic when it is originating from the public network and traveling to the DMZ network?  
**Choices:**  
A. Traffic that is originating from the public network is inspected and selectively permitted when traveling to the DMZ network.  
B. Traffic that is originating from the public network is usually permitted with little or no restriction when traveling to the DMZ network.  
C. Traffic that is originating from the public network is usually forwarded without inspection when traveling to the DMZ network.  
D. Traffic that is originating from the public network is usually blocked when traveling to the DMZ network.

---

**Question 84:**  
A client connects to a Web server. Which component of this HTTP connection is not examined by a stateful firewall?  
**Choices:**  
A. the source IP address of the client traffic  
B. the destination port number of the client traffic  
C. the actual contents of the HTTP connection  
D. the source port number of the client traffic

---

**Question 85:**  
Which network monitoring technology uses VLANs to monitor traffic on remote switches?  
**Choices:**  
A. IPS  
B. IDS  
C. TAP  
D. RSPAN

---

**Question 86:**  
Which rule action will cause Snort IPS to block and log a packet?  
**Choices:**  
A. log  
B. drop  
C. alert  
D. Sdrop

---

**Question 87:**  
What is typically used to create a security trap in the data center facility?  
**Choices:**  
A. IDs, biometrics, and two access doors  
B. high resolution monitors  
C. redundant authentication servers  
D. a server without all security patches applied

---

**Question 88:**  
A company is concerned with leaked and stolen corporate data on hard copies. Which data loss mitigation technique could help with this situation?  
**Choices:**  
A. strong PC security settings  
B. strong passwords  
C. shredding  
D. encryption

---

**Question 89:**  
Upon completion of a network security course, a student decides to pursue a career in cryptanalysis. What job would the student be doing as a cryptanalyst?  
**Choices:**  
A. cracking code without access to the shared secret key  
B. creating hashing codes to authenticate data  
C. making and breaking secret codes  
D. creating transposition and substitution ciphers

---

**Question 90:**  
What command is used on a switch to set the port access entity type so the interface acts only as an authenticator and will not respond to any messages meant for a supplicant?  
**Choices:**  
A. dot1x pae authenticator  
B. authentication port-control auto  
C. aaa authentication dot1x default group radius  
D. dot1x system-auth-control

---

**Question 91:**  
Which two disadvantages of using an IDS are true? (Choose two.)  
**Choices:**  
A. The IDS does not stop malicious traffic.  
B. The IDS works offline using copies of network traffic.  
C. The IDS has no impact on traffic.  
D. The IDS analyzes actual forwarded packets.  
E. The IDS requires other devices to respond to attacks.

---

**Question 92:**  
Refer to the exhibit. The `ip verify source` command is applied on untrusted interfaces. Which type of attack is mitigated by using this configuration?  
**Choices:**  
A. DHCP spoofing  
B. DHCP starvation  
C. STP manipulation  
D. MAC and IP address spoofing

---

**Question 93:**  
What ports can receive forwarded traffic from an isolated port that is part of a PVLAN?  
**Choices:**  
A. other isolated ports and community ports  
B. only promiscuous ports  
C. all other ports within the same community  
D. only isolated ports

---

**Question 94:**  
A user complains about being locked out of a device after too many unsuccessful AAA login attempts. What could be used by the network administrator to provide a secure authentication access method without locking a user out of a device?  
**Choices:**  
A. Use the login delay command for authentication attempts.  
B. Use the login local command for authenticating user access.  
C. Use the aaa local authentication attempts max-fail global configuration mode command with a higher number of acceptable failures.  
D. Use the none keyword when configuring the authentication method list.

---

**Question 95:**  
What are two drawbacks in assigning user privilege levels on a Cisco router? (Choose two.)  
**Choices:**  
A. Only a root user can add or remove commands.  
B. Privilege levels must be set to permit access control to specific device interfaces, ports, or slots.  
C. Assigning a command with multiple keywords allows access to all commands using those keywords.  
D. Commands from a lower level are always executable at a higher level.  
E. AAA must be enabled.

---

**Question 96:**  
Refer to the exhibit. Which conclusion can be made from the `show crypto map` command output that is shown on R1?  
**Choices:**  
A. The crypto map has not yet been applied to an interface.  
B. The current peer IP address should be 172.30.2.1.  
C. There is a mismatch between the transform sets.  
D. The tunnel configuration was established and can be tested with extended pings.

---

**Question 97:**  
What are two reasons to enable OSPF routing protocol authentication on a network? (Choose two.)  
**Choices:**  
A. to prevent data traffic from being redirected and then discarded  
B. to ensure faster network convergence  
C. to provide data security through encryption  
D. to prevent redirection of data traffic to an insecure link  
E. to ensure more efficient routing

---

**Question 98:**  
Which three functions are provided by the syslog logging service? (Choose three.)  
**Choices:**  
A. gathering logging information  
B. authenticating and encrypting data sent over the network  
C. retaining captured messages on the router when a router is rebooted  
D. specifying where captured information is stored  
E. distinguishing between information to be captured and information to be ignored  
F. setting the size of the logging buffer

---

**Question 99:**  
What two ICMPv6 message types must be permitted through IPv6 access control lists to allow resolution of Layer 3 addresses to Layer 2 MAC addresses? (Choose two.)  
**Choices:**  
A. neighbor solicitations  
B. echo requests  
C. neighbor advertisements  
D. echo replies  
E. router solicitations  
F. router advertisements

---

**Question 100:**  
Which three services are provided through digital signatures? (Choose three.)  
**Choices:**  
A. accounting  
B. authenticity  
C. compression  
D. nonrepudiation  
E. integrity  
F. encryption

---

**Question 101:**  
A technician is to document the current configurations of all network devices in a college, including those in off-site buildings. Which protocol would be best to use to securely access the network devices?  
**Choices:**  
A. FTP  
B. HTTP  
C. SSH  
D. Telnet

---

**Question 102:**  
An administrator is trying to develop a BYOD security policy for employees that are bringing a wide range of devices to connect to the company network. Which three objectives must the BYOD security policy address? (Choose three.)  
**Choices:**  
A. All devices must be insured against liability if used to compromise the corporate network.  
B. All devices must have open authentication with the corporate network.  
C. Rights and activities permitted on the corporate network must be defined.  
D. Safeguards must be put in place for any personal device being compromised.  
E. The level of access of employees when connecting to the corporate network must be defined.  
F. All devices should be allowed to attach to the corporate network flawlessly.

---

**Question 103:**  
What is the function of the pass action on a Cisco IOS Zone-Based Policy Firewall?  
**Choices:**  
A. logging of rejected or dropped packets  
B. inspecting traffic between zones for traffic control  
C. tracking the state of connections between zones  
D. forwarding traffic from one zone to another

---

**Question 104:**  
Refer to the exhibit. Based on the security levels of the interfaces on ASA1, what traffic will be allowed on the interfaces?  
**Choices:**  
A. Traffic from the Internet and DMZ can access the LAN.  
B. Traffic from the Internet and LAN can access the DMZ.  
C. Traffic from the Internet can access both the DMZ and the LAN.  
D. Traffic from the LAN and DMZ can access the Internet.

---

**Question 105:**  
What network testing tool can be used to identify network layer protocols running on a host?  
**Choices:**  
A. SIEM  
B. Nmap  
C. L0phtcrack  
D. Tripwire

---

**Question 106:**  
In the implementation of security on multiple devices, how do ASA ACLs differ from Cisco IOS ACLs?  
**Choices:**  
A. Cisco IOS routers utilize both named and numbered ACLs and Cisco ASA devices utilize only numbered ACLs.  
B. Cisco IOS ACLs are configured with a wildcard mask and Cisco ASA ACLs are configured with a subnet mask.  
C. Cisco IOS ACLs are processed sequentially from the top down and Cisco ASA ACLs are not processed sequentially.  
D. Cisco IOS ACLs utilize an implicit deny all and Cisco ASA ACLs end with an implicit permit all.

---

**Question 107:**  
Which statement describes an important characteristic of a site-to-site VPN?  
**Choices:**  
A. It must be statically set up.  
B. It is ideally suited for use by mobile workers.  
C. It requires using a VPN client on the host PC.  
D. After the initial connection is established, it can dynamically change connection information.  
E. It is commonly implemented over dialup and cable modem networks.

---

**Question 108:**  
Which two options are security best practices that help mitigate BYOD risks? (Choose two.)  
**Choices:**  
A. Use paint that reflects wireless signals and glass that prevents the signals from going outside the building.  
B. Keep the device OS and software updated.  
C. Only allow devices that have been approved by the corporate IT team.  
D. Only turn on Wi-Fi when using the wireless network.  
E. Decrease the wireless antenna gain level.

---

**Question 109:**  
Refer to the exhibit. A network administrator configures AAA authentication on R1. Which statement describes the effect of the keyword single-connection in the configuration?  
**Choices:**  
A. R1 will open a separate connection to the TACACS+ server for each user authentication session.  
B. The authentication performance is enhanced by keeping the connection to the TACACS+ server open.  
C. The TACACS+ server only accepts one successful try for a user to authenticate with it.  
D. R1 will open a separate connection to the TACACS server on a per source IP address basis for each authentication session.

---

**Question 110:**  
A recently created ACL is not working as expected. The admin determined that the ACL had been applied inbound on the interface and that was the incorrect direction. How should the admin fix this issue?  
**Choices:**  
A. Delete the original ACL and create a new ACL, applying it outbound on the interface.  
B. Add an association of the ACL outbound on the same interface.  
C. Fix the ACE statements so that it works as desired inbound on the interface.  
D. Remove the inbound association of the ACL on the interface and reapply it outbound.

---

**Question 111:**  
Which statement describes an important characteristic of the Snort term-based subscriptions that is true for both the community and the subscriber rule sets?  
**Choices:**  
A. Both have a 30-day delayed access to updated signatures.  
B. Both use Cisco Talos to provide coverage in advance of exploits.  
C. Both are fully supported by Cisco and include Cisco customer support.  
D. Both offer threat protection against security threats.

---

**Question 112:**  
A security analyst is configuring Snort IPS. The analyst has just downloaded and installed the Snort OVA file. What is the next step?  
**Choices:**  
A. Verify Snort IPS.  
B. Configure Virtual Port Group interfaces.  
C. Enable IPS globally or on desired interfaces.  
D. Activate the virtual services.

---

**Question 113:**  
The security policy in a company specifies that employee workstations can initiate HTTP and HTTPS connections to outside websites and the return traffic is allowed. However, connections initiated from outside hosts are not allowed. Which parameter can be used in extended ACLs to meet this requirement?  
**Choices:**  
A. dscp  
B. precedence  
C. eq  
D. established

---

**Question 114:**  
A researcher is comparing the differences between a stateless firewall and a proxy firewall. Which two additional layers of the OSI model are inspected by a proxy firewall? (Choose two.)  
**Choices:**  
A. Layer 3  
B. Layer 4  
C. Layer 5  
D. Layer 6  
E. Layer 7

---

**Question 115:**  
Refer to the exhibit. A network administrator is configuring a VPN between routers R1 and R2. Which commands would correctly configure a pre-shared key for the two routers?  
**Choices:**  
A.  
  R1(config)# username R2 password 5tayout!  
  R2(config)# username R1 password 5tayout!  
B.  
  R1(config)# crypto isakmp key 5tayout! address 64.100.0.2  
  R2(config)# crypto isakmp key 5tayout! address 64.100.0.1  
C.  
  R1(config)# crypto isakmp key 5tayout! address 64.100.0.227  
  R2(config)# crypto isakmp key 5tayout! address 64.100.0.226  
D.  
  R1(config-if)# ppp pap sent-username R1 password 5tayout!  
  R2(config-if)# ppp pap sent-username R2 password 5tayout!

---

**Question 116:**  
Refer to the exhibit. Which statement is true about the effect of this Cisco IOS zone-based policy firewall configuration?  
**Choices:**  
A. The firewall will automatically drop all HTTP, HTTPS, and FTP traffic.  
B. The firewall will automatically allow HTTP, HTTPS, and FTP traffic from s0/0/0 to g0/0 and will track the connections. Tracking the connection allows only return traffic to be permitted through the firewall in the opposite direction.  
C. The firewall will automatically allow HTTP, HTTPS, and FTP traffic from s0/0/0 to g0/0, but will not track the state of connections. A corresponding policy must be applied to allow return traffic to be permitted through the firewall in the opposite direction.  
D. The firewall will automatically allow HTTP, HTTPS, and FTP traffic from g0/0 to s0/0/0 and will track the connections. Tracking the connection allows only return traffic to be permitted through the firewall in the opposite direction.

---

**Question 117:**  
Which privilege level has the most access to the Cisco IOS?  
**Choices:**  
A. level 0  
B. level 15  
C. level 7  
D. level 16  
E. level 1

---

**Question 118:**  
Refer to the exhibit. A network administrator has configured NAT on an ASA device. What type of NAT is used?  
**Choices:**  
A. inside NAT  
B. static NAT  
C. bidirectional NAT  
D. outside NAT

---

**Question 119:**  
A network analyst is configuring a site-to-site IPsec VPN. The analyst has configured both the ISAKMP and IPsec policies. What is the next step?  
**Choices:**  
A. Configure the hash as SHA and the authentication as pre-shared.  
B. Apply the crypto map to the appropriate outbound interfaces.  
C. Issue the show crypto ipsec sa command to verify the tunnel.  
D. Verify that the security feature is enabled in the IOS.

---

**Question 120:**  
When an inbound Internet-traffic ACL is being implemented, what should be included to prevent the spoofing of internal networks?  
**Choices:**  
A. ACEs to prevent traffic from private address spaces  
B. ACEs to prevent broadcast address traffic  
C. ACEs to prevent ICMP traffic  
D. ACEs to prevent HTTP traffic  
E. ACEs to prevent SNMP traffic

---

**Question 121:**  
*Match the security term to the appropriate description.*  
*(Image-based matching – please refer to the original exhibit for the complete matching options.)*

---

**Question 122:**  
Which two types of attacks are examples of reconnaissance attacks? (Choose two.)  
**Choices:**  
A. brute force  
B. port scan  
C. ping sweep  
D. man-in-the-middle  
E. SYN flood

---

**Question 123:**  
Which Cisco solution helps prevent ARP spoofing and ARP poisoning attacks?  
**Choices:**  
A. Dynamic ARP Inspection  
B. IP Source Guard  
C. DHCP Snooping  
D. Port Security

---

**Question 124:**  
When the Cisco NAC appliance evaluates an incoming connection from a remote device against the defined network policies, what feature is being used?  
**Choices:**  
A. posture assessment  
B. remediation of noncompliant systems  
C. authentication and authorization  
D. quarantining of noncompliant systems

---

**Question 125:**  
Which two steps are required before SSH can be enabled on a Cisco router? (Choose two.)  
**Choices:**  
A. Give the router a host name and domain name.  
B. Create a banner that will be displayed to users when they connect.  
C. Generate a set of secret keys to be used for encryption and decryption.  
D. Set up an authentication server to handle incoming connection requests.  
E. Enable SSH on the physical interfaces where the incoming connection requests will be received.

---

**Question 126:**  
The network administrator for an e-commerce website requires a service that prevents customers from claiming that legitimate orders are fake. What service provides this type of guarantee?  
**Choices:**  
A. confidentiality  
B. authentication  
C. integrity  
D. nonrepudiation

---

**Question 127:**  
*Match the security technology with the description.*  
*(Image-based matching – please refer to the original exhibit for the complete matching options.)*

---

**Question 128:**  
What functionality is provided by Cisco SPAN in a switched network?  
**Choices:**  
A. It mirrors traffic that passes through a switch port or VLAN to another port for traffic analysis.  
B. It prevents traffic on a LAN from being disrupted by a broadcast storm.  
C. It protects the switched network from receiving BPDUs on ports that should not be receiving them.  
D. It copies traffic that passes through a switch interface and sends the data directly to a syslog or SNMP server for analysis.  
E. It inspects voice protocols to ensure that SIP, SCCP, H.323, and MGCP requests conform to voice standards.  
F. It mitigates MAC address overflow attacks.

---

**Question 129:**  
Which three statements are generally considered to be best practices in the placement of ACLs? (Choose three.)  
**Choices:**  
A. Filter unwanted traffic before it travels onto a low-bandwidth link.  
B. Place standard ACLs close to the destination IP address of the traffic.  
C. Place standard ACLs close to the source IP address of the traffic.  
D. Place extended ACLs close to the destination IP address of the traffic.  
E. Place extended ACLs close to the source IP address of the traffic.  
F. For every inbound ACL placed on an interface, there should be a matching outbound ACL.

---

**Question 130:**  
What function is performed by the class maps configuration object in the Cisco modular policy framework?  
**Choices:**  
A. identifying interesting traffic  
B. applying a policy to an interface  
C. applying a policy to interesting traffic  
D. restricting traffic through an interface

---

**Question 131:**  
In an attempt to prevent network attacks, cyber analysts share unique identifiable attributes of known attacks with colleagues. What three types of attributes or indicators of compromise are helpful to share? (Choose three.)  
**Choices:**  
A. IP addresses of attack servers  
B. changes made to end system software  
C. netbios names of compromised firewalls  
D. features of malware files  
E. BIOS of attacking systems  
F. system ID of compromised systems

---

**Question 132:**  
What two assurances does digital signing provide about code that is downloaded from the Internet? (Choose two.)  
**Choices:**  
A. The code is authentic and is actually sourced by the publisher.  
B. The code has not been modified since it left the software publisher.  
C. The code was encrypted with both a private and public key.  
D. The code contains no viruses.  
E. The code contains no errors.

---

**Question 133:**  
Refer to the exhibit. What algorithm is being used to provide public key exchange?  
**Choices:**  
A. SHA  
B. RSA  
C. Diffie-Hellman  
D. AES

---

**Question 134:**  
Which two statements describe the use of asymmetric algorithms? (Choose two.)  
**Choices:**  
A. Public and private keys may be used interchangeably.  
B. If a public key is used to encrypt the data, a public key must be used to decrypt the data.  
C. If a private key is used to encrypt the data, a public key must be used to decrypt the data.  
D. If a public key is used to encrypt the data, a private key must be used to decrypt the data.  
E. If a private key is used to encrypt the data, a private key must be used to decrypt the data.

---

**Question 135:**  
Which statement is a feature of HMAC?  
**Choices:**  
A. HMAC uses a secret key that is only known to the sender and defeats man-in-the-middle attacks.  
B. HMAC uses protocols such as SSL or TLS to provide session layer confidentiality.  
C. HMAC uses a secret key as input to the hash function, adding authentication to integrity assurance.  
D. HMAC is based on the RSA hash function.

---

**Question 136:**  
What is the purpose of the webtype ACLs in an ASA?  
**Choices:**  
A. to inspect outbound traffic headed towards certain web sites  
B. to restrict traffic that is destined to an ASDM  
C. to filter traffic for clientless SSL VPN users  
D. to monitor return traffic that is in response to web server requests that are initiated from the inside interface

---

**Question 137:**  
Which two statements describe the effect of the access control list wildcard mask 0.0.0.15? (Choose two.)  
**Choices:**  
A. The first 32 bits of a supplied IP address will be matched.  
B. The last four bits of a supplied IP address will be ignored.  
C. The last five bits of a supplied IP address will be ignored.  
D. The first 28 bits of a supplied IP address will be matched.  
E. The first 28 bits of a supplied IP address will be ignored.  
F. The last four bits of a supplied IP address will be matched.

---

**Question 138:**  
Which type of firewall is the most common and allows or blocks traffic based on Layer 3, Layer 4, and Layer 5 information?  
**Choices:**  
A. stateless firewall  
B. packet filtering firewall  
C. next generation firewall  
D. stateful firewall

---

**Question 139:**  
Which protocol or measure should be used to mitigate the vulnerability of using FTP to transfer documents between a teleworker and the company file server?  
**Choices:**  
A. SCP  
B. TFTP  
C. ACLs on the file server  
D. out-of-band communication channel

---

**Question 140:**  
Refer to the exhibit. The IPv6 access list LIMITED_ACCESS is applied on the S0/0/0 interface of R1 in the inbound direction. Which IPv6 packets from the ISP will be dropped by the ACL on R1?  
**Choices:**  
A. HTTPS packets to PC1  
B. ICMPv6 packets that are destined to PC1  
C. packets that are destined to PC1 on port 80  
D. neighbor advertisements that are received from the ISP router

---

**Question 141:**  
What tool is available through the Cisco IOS CLI to initiate security audits and to make recommended configuration changes with or without administrator input?  
**Choices:**  
A. Control Plane Policing  
B. Cisco AutoSecure  
C. Cisco ACS  
D. Simple Network Management Protocol

---

**Question 142:**  
Refer to the exhibit. Which pair of crypto isakmp key commands would correctly configure PSK on the two routers?  
**Choices:**  
A.  
  R1(config)# crypto isakmp key cisco123 address 209.165.200.227  
  R2(config)# crypto isakmp key cisco123 address 209.165.200.226  
B.  
  R1(config)# crypto isakmp key cisco123 address 209.165.200.226  
  R2(config)# crypto isakmp key cisco123 address 209.165.200.227  
C.  
  R1(config)# crypto isakmp key cisco123 hostname R1  
  R2(config)# crypto isakmp key cisco123 hostname R2  
D.  
  R1(config)# crypto isakmp key cisco123 address 209.165.200.226  
  R2(config)# crypto isakmp key secure address 209.165.200.227

---

**Question 143:**  
Which two technologies provide enterprise-managed VPN solutions? (Choose two.)  
**Choices:**  
A. Layer 3 MPLS VPN  
B. Frame Relay  
C. site-to-site VPN  
D. Layer 2 MPLS VPN  
E. remote access VPN

---

**Question 144:**  
What are the three components of an STP bridge ID? (Choose three.)  
**Choices:**  
A. the date and time that the switch was brought online  
B. the hostname of the switch  
C. the MAC address of the switch  
D. the extended system ID  
E. the bridge priority value  
F. the IP address of the management VLAN

---

**Question 145:**  
What are two differences between stateful and packet filtering firewalls? (Choose two.)  
**Choices:**  
A. A packet filtering firewall will prevent spoofing by determining whether packets belong to an existing connection while a stateful firewall follows pre-configured rule sets.  
B. A stateful firewall provides more stringent control over security than a packet filtering firewall.  
C. A packet filtering firewall is able to filter sessions that use dynamic port negotiations while a stateful firewall cannot.  
D. A stateful firewall will provide more logging information than a packet filtering firewall.  
E. A stateful firewall will examine each packet individually while a packet filtering firewall observes the state of a connection.

---

**Question 146:**  
Which portion of the Snort IPS rule header identifies the destination port?  
**Choices:**  
A. alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS  
B. any  
C. $HTTP_PORTS  
D. $HOME_NET  
E. tcp

---

**Question 147:**  
Match each SNMP operation to the corresponding description.  
*Place the options in the following order:*  
**Choices:**  
A. set-request – storing a value in a specific variable  
B. get-bulk-request – retrieving multiple rows in a table in a single transmission  
C. get-next-request – sequentially searching tables to retrieve a value from a variable  
D. get-response – replying to GET request and SET request messages that are sent by an NMS

---

**Question 148:**  
What port state is used by 802.1X if a workstation fails authorization?  
**Choices:**  
A. disabled  
B. down  
C. unauthorized  
D. blocking

---

**Question 149:**  
Match the ASA special hardware modules to the description.  
*Refer to the exhibit for the options (e.g., AIP module, CSC module, AIP-SSM/AIP-SSC, etc.).*

---

**Question 150:**  
Refer to the exhibit. Which two ACLs, if applied to the G0/1 interface of R2, would permit only the two LAN networks attached to R1 to access the network that connects to the R2 G0/1 interface? (Choose two.)  
**Choices:**  
A. access-list 3 permit 192.168.10.128 0.0.0.63  
B. access-list 1 permit 192.168.10.0 0.0.0.127  
C. access-list 4 permit 192.168.10.0 0.0.0.255  
D. access-list 2 permit host 192.168.10.9  
E. access-list 2 permit host 192.168.10.69  
F. access-list 5 permit 192.168.10.0 0.0.0.63  
G. access-list 5 permit 192.168.10.64 0.0.0.63

---

**Question 151:**  
Which two characteristics apply to role-based CLI access superviews? (Choose two.)  
**Choices:**  
A. A specific superview cannot have commands added to it directly.  
B. CLI views have passwords, but superviews do not have passwords.  
C. A single superview can be shared among multiple CLI views.  
D. Deleting a superview deletes all associated CLI views.  
E. Users logged in to a superview can access all commands specified within the associated CLI views.

---

**Question 152:**  
Match the IPS alarm type to the description.  
*Place the options in the following order:*  
**Choices:**  
A. true negative – normal user traffic is not generating an alarm  
B. false positive – normal user traffic is generating an alarm  
C. true positive – verified attack traffic is generating an alarm  
D. false negative – attack traffic is not generating an alarm

---

**Question 153:**  
What are two security features commonly found in a WAN design? (Choose two.)  
**Choices:**  
A. WPA2 for data encryption of all data between sites  
B. firewalls protecting the main and remote sites  
C. outside perimeter security including continuous video surveillance  
D. port security on all user-facing ports  
E. VPNs used by mobile workers between sites

---

 