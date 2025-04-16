Here are your Network Security (Version 1.0) Practice Final Answers MCQs with formatting:

**1.** Which two statements are true about ASA standard ACLs? (Choose two.)
    a) They identify only the destination IP address.
    b) They are the most common type of ACL.
    c) They are applied to interfaces to control traffic.
    d) They specify both the source and destination MAC address.
    e) They are typically only used for OSPF routes.

**2.** When dynamic NAT on an ASA is being configured, what two parameters must be specified by network objects? (Choose two.)
    a) the inside NAT interface
    b) the interface security level
    c) the outside NAT interface
    d) a range of private addresses that will be translated
    e) the pool of public global addresses

**3.** Which protocol uses X.509 certificates to support mail protection performed by mail agents?
    a) IPsec
    b) SSL
    c) S/MIME
    d) EAP-TLS

**4.** What are two security features commonly found in a WAN design? (Choose two.)
    a) WPA2 for data encryption of all data between sites
    b) firewalls protecting the main and remote sites
    c) outside perimeter security including continuous video surveillance
    d) port security on all user-facing ports
    e) VPNs used by mobile workers between sites

**5.** What is an appropriate use for class 5 digital certificates?
    a) used for online business transactions between companies
    b) used for private organizations or government security
    c) used by organizations for which proof of identity is required
    d) used for testing in situations in which no checks have been performed

**6.** Which two statements are characteristics of a virus? (Choose two.)
    a) A virus typically requires end-user activation.
    b) A virus has an enabling vulnerability, a propagation mechanism, and a payload.
    c) A virus replicates itself by independently exploiting vulnerabilities in networks.
    d) A virus provides the attacker with sensitive data, such as passwords.
    e) A virus can be dormant and then activate at a specific time or date.

**7.** Match the information security component with the description.
    a) Confidentiality
    b) Integrity
    c) Availability

    i. ensures that data is accessible to authorized users when needed
    ii. prevents unauthorized disclosure of information
    iii. guarantees that data is accurate and has not been altered

**8.** Match the security policy with the description. (Not all options are used.)
    a) acceptable use policy (AUP)
    b) remote access policy
    c) identification and authentication policy
    d) network maintenance policy
    e) incident response policy

    i. identifies network applications and uses that are acceptable to the organization
    ii. identifies how remote users can access a network and what is accessible via remote connectivity
    iii. specifies authorized persons that can have access to network resources and identity verification procedures
    iv. specifies network device operating systems and end user application update procedures

**9.** How does the `service password-encryption` command enhance password security on Cisco routers and switches?
    a) It encrypts passwords as they are sent across the network.
    b) It encrypts passwords that are stored in router or switch configuration files.
    c) It requires that a user type encrypted passwords to gain console access to a router or switch.
    d) It requires encrypted passwords to be used when connecting remotely to a router or switch with Telnet.

**10.** Which benefit does SSH offer over Telnet for remotely managing a router?
    a) encryption
    b) TCP usage
    c) authorization
    d) connections via multiple VTY lines

**11.** Refer to the exhibit. Which statement about the JR-Admin account is true?
    a) JR-Admin can issue `show`, `ping`, and `reload` commands.
    b) JR-Admin can issue `ping` and `reload` commands.
    c) JR-Admin can issue only `ping` commands.
    d) JR-Admin can issue `debug` and `reload` commands.
    e) JR-Admin cannot issue any command because the privilege level does not match one of those defined.

**12.** What protocol is used by SCP for secure transport?
    a) IPSec
    b) HTTPS
    c) SSH
    d) Telnet
    e) TFTP

**13.** Refer to the exhibit. What type of syslog message is displayed?
    a) warning
    b) notification
    c) informational
    d) debugging

**14.** What command must be issued on a Cisco router that will serve as an authoritative NTP server?
    a) `ntp master 1`
    b) `ntp server 172.16.0.1`
    c) `ntp broadcast client`
    d) `clock set 11:00:00 DEC 20 2010`

**15.** A server log includes this entry: User student accessed host server ABC using Telnet yesterday for 10 minutes. What type of log entry is this?
    a) authentication
    b) authorization
    c) accounting
    d) accessing

**16.** Which three types of views are available when configuring the role-based CLI access feature? (Choose three.)
    a) superuser view
    b) root view
    c) superview
    d) CLI view
    e) admin view
    f) config view

**17.** What is the purpose of using the `ip ospf message-digest-key key md5 password` command and the `area area-id authentication message-digest` command on a router?
    a) to encrypt OSPF routing updates
    b) to enable OSPF MD5 authentication on a per-interface basis
    c) to configure OSPF MD5 authentication globally on the router
    d) to facilitate the establishment of neighbor adjacencies

**18.** What is indicated by the use of the `local-case` keyword in a local AAA authentication configuration command sequence?
    a) that user access is limited to vty terminal lines
    b) that passwords and usernames are case-sensitive
    c) that AAA is enabled globally on the router
    d) that a default local database AAA authentication is applied to all lines

**19.** A network administrator is configuring an AAA server to manage RADIUS authentication. Which two features are included in RADIUS authentication? (Choose two.)
    a) encryption for all communication
    b) hidden passwords during transmission
    c) single process for authentication and authorization
    d) separate processes for authentication and authorization
    e) encryption for only the data

**20.** A network administrator is explaining to a junior colleague the use of the `lt` and `gt` keywords when filtering packets using an extended ACL. Where would the `lt` or `gt` keywords be used?
    a) in an IPv6 extended ACL that stops packets going to one specific destination VLAN
    b) in an IPv4 named standard ACL that has specific UDP protocols that are allowed to be used on a specific server
    c) in an IPv6 named ACL that permits FTP traffic from one particular LAN getting to another LAN
    d) in an IPv4 extended ACL that allows packets from a range of TCP ports destined for a specific network device

**21.** Which feature is unique to IPv6 ACLs when compared to those of IPv4 ACLs?
    a) the use of wildcard masks
    b) an implicit `deny any any` statement
    c) the use of named ACL statements
    d) an implicit permit of neighbor discovery packets

**22.** Refer to the exhibit. An extended access list has been created to prevent human resource users from gaining access to the accounting server. All other network traffic is to be permitted. When following the ACL configuration guidelines, on which router, interface, and direction should the access list be applied?
    a) router R1, interface S0/1/0, outbound
    b) router R2, interface Gi0/0/1, outbound
    c) router R2, interface Gi0/0/1, inbound
    d) router R1, interface Gi0/0/0, inbound
    e) router R2, interface S0/1/1, inbound
    f) router R1, interface Gi0/0/0, outbound

**23.** Which statement describes the characteristics of packet-filtering and stateful firewalls as they relate to the OSI model?
    a) Both stateful and packet-filtering firewalls can filter at the application layer.
    b) A stateful firewall can filter application layer information, whereas a packet-filtering firewall cannot filter beyond the network layer.
    c) A packet-filtering firewall typically can filter up to the transport layer, whereas a stateful firewall can filter up to the session layer.
    d) A packet-filtering firewall uses session layer information to track the state of a connection, whereas a stateful firewall uses application layer information to track the state of a connection.

**24.** Which special hardware module, when integrated into ASA, provides advanced IPS features?
    a) Content Security and Control (CSC)
    b) Advanced Inspection and Prevention (AIP)
    c) Advanced Inspection and Prevention Security Services Card (AIP-SSC)
    d) Advanced Inspection and Prevention Security Services Module (AIP-SSM)

**25.** Refer to the exhibit. A network administrator is configuring the security level for the ASA. What is a best practice for assigning the security level on the three interfaces?
    a) Outside 0, Inside 35, DMZ 90
    b) Outside 40, Inside 100, DMZ 0
    c) Outside 0, Inside 100, DMZ 50
    d) Outside 100, Inside 10, DMZ 40

**26.** What is an advantage in using a packet filtering firewall versus a high-end firewall appliance?
    a) Packet filters perform almost all the tasks of a high-end firewall at a fraction of the cost.
    b) Packet filters represent a complete firewall solution.
    c) Packet filters are not susceptible to IP spoofing.
    d) Packet filters provide an initial degree of security at the data-link and network layer.

**27.** Which type of firewall is commonly part of a router firewall and allows or blocks traffic based on Layer 3 and Layer 4 information?
    a) stateless firewall
    b) stateful firewall
    c) proxy firewall
    d) application gateway firewall

**28.** A company is deploying a new network design in which the border router has three interfaces. Interface Serial0/0/0 connects to the ISP, GigabitEthernet0/0 connects to the DMZ, and GigabitEthernet/01 connects to the internal private network. Which type of traffic would receive the least amount of inspection (have the most freedom of travel)?
    a) traffic that is going from the private network to the DMZ
    b) traffic that originates from the public network and that is destined for the DMZ
    c) traffic that is returning from the DMZ after originating from the private network
    d) traffic that is returning from the public network after originating from the private network

**29.** What are two benefits offered by a zone-based policy firewall on a Cisco router? (Choose two.)
    a) Policies are defined exclusively with ACLs.
    b) Policies are applied to unidirectional traffic between zones.
    c) Policies provide scalability because they are easy to read and troubleshoot.
    d) Any interface can be configured with both a ZPF and an IOS Classic Firewall.
    e) Virtual and physical interfaces are put in different zones to enhance security.

**30.** When a Cisco IOS Zone-Based Policy Firewall is being configured via CLI, which step must be taken after zones have been created?
    a) Design the physical infrastructure.
    b) Establish policies between zones.
    c) Identify subsets within zones.
    d) Assign interfaces to zones.

**31.** What are two shared characteristics of the IDS and the IPS? (Choose two.)
    a) Both are deployed as sensors.
    b) Both analyze copies of network traffic.
    c) Both use signatures to detect malicious traffic.
    d) Both have minimal impact on network performance.
    e) Both rely on an additional network device to respond to malicious traffic.

**32.** When a Cisco IOS Zone-Based Policy Firewall is being configured, which two actions can be applied to a traffic class? (Choose two.)
    a) log
    b) hold
    c) drop
    d) inspect
    e) copy
    f) forward

**33.** Match the network security device type with the description.
    a) Firewall
    b) IDS
    c) IPS

    i. actively prevents malicious traffic from entering the network
    ii. monitors network traffic for suspicious activity and alerts administrators
    iii. controls network access and protects resources by examining incoming and outgoing traffic

**34.** What is a characteristic of an IPS atomic signature?
    a) it can be slow and inefficient to analyze traffic
    b) it requires several pieces of data to match an attack
    c) it is a stateful signature
    d) it is the simplest type of signature

**35.** Match each IPS signature trigger category with the description.
    a) String/Pattern
    b) Context
    c) Atomic

    i. looks for specific sequences of bytes within a packet
    ii. looks for a single event or packet that matches a known attack
    iii. looks at multiple events or conditions to identify malicious activity

**36.** A company is concerned about data theft if any of the corporate laptops are stolen. Which Windows tool would the company use to protect the data on the laptops?
    a) AMP
    b) 802.1X
    c) RADIUS
    d) BitLocker

**37.** What protocol is used to encapsulate the EAP data between the authenticator and authentication server performing 802.1X authentication?
    a) RADIUS
    b) TACACS+
    c) SSH
    d) MD5

**38.** A company requires the use of 802.1X security. What type of traffic can be sent if the `authentication port-control auto` command is configured, but the client has not yet been authenticated?
    a) SNMP
    b) EAPOL
    c) broadcasts such as ARP
    d) any data encrypted with 3DES or AES

**39.** Which two security features can cause a switch port to become error-disabled? (Choose two.)
    a) root guard
    b) PortFast with BPDU guard enabled
    c) protected ports
    d) storm control with the trap option
    e) port security with the shutdown violation mode

**40.** What are three techniques for mitigating VLAN hopping attacks? (Choose three.)
    a) Disable DTP.
    b) Enable trunking manually.
    c) Set the native VLAN to an unused VLAN.
    d) Enable BPDU guard.
    e) Enable Source Guard.
    f) Use private VLANs.

**41.** Refer to the exhibit. A network administrator is configuring DAI on switch SW1. What is the result of entering the exhibited commands?
    a) DAI will validate both source and destination MAC addresses as well as the IP addresses in the order specified. If all parameters are valid then the ARP packet is allowed to pass.
    b) DAI will validate both source and destination MAC addresses as well as the IP addresses in the order specified. When one set of parameters are valid, the ARP packet is allowed to pass.
    c) DAI will validate only the destination MAC addresses.
    d) DAI will validate only the IP addresses.

**42.** During a recent pandemic, employees from ABC company were allowed to work from home. What security technology should be implemented to ensure that data communications between the employees and the ABC Head Office network remain confidential?
    a) a symmetric or asymmetric encryption algorithm such as AES or PKI
    b) a hashing algorithm such as MD5
    c) a hash message authentication code such as HMAC
    d) a hash-generating algorithm such as SHA

**43.** Which cipher played a significant role in World War II?
    a) RC4
    b) Caesar
    c) Enigma
    d) One-time pad

**44.** One method used by Cryptanalysts to crack codes is based on the fact that some letters of the English language are used more often than others. Which term is used to describe this method?
    a) cybertext
    b) meet-in-the-middle
    c) frequency analysis
    d) known-plaintext

**45.** Why are DES keys considered weak keys?
    a) They are more resource intensive.
    b) DES weak keys are difficult to manage.
    c) They produce identical subkeys.
    d) DES weak keys use very long key sizes.

**46.** Refer to the exhibit. A network administrator is configuring an object group on an ASA device. Which configuration keyword should be used after the object group name `SERVICE1`?
    a) ip
    b) tcp
    c) udp
    d) icmp

**47.** In the implementation of network security, how does the deployment of a Cisco ASA firewall differ from a Cisco IOS router?
    a) ASA devices use ACLs that are always numbered.
    b) ASA devices do not support an implicit deny within ACLs.
    c) ASA devices support interface security levels.
    d) ASA devices use ACLs configured with a wildcard mask.

**48.** Refer to the exhibit. A network administrator is configuring PAT on an ASA device to enable internal workstations to access the Internet. Which configuration command should be used next?
    a) `nat (inside,outside) dynamic NET1`
    b) `nat (outside,inside) dynamic NET1`
    c) `nat (inside,outside) dynamic interface`
    d) `nat (outside,inside) dynamic interface`

**49.** What type of network security test uses simulated attacks to determine the feasibility of an attack as well as the possible consequences if the attack occurs?
    a) penetration testing
    b) network scanning
    c) integrity checking
    d) vulnerability scanning

**50.** What three tasks can a network administrator accomplish with the Nmap and Zenmap security testing tools? (Choose three.)
 
Gotcha! Here are the questions and their multiple-choice options for questions 50 through 64:

**50. What three tasks can a network administrator accomplish with the Nmap and Zenmap security testing tools? (Choose three.)**
    * operating system fingerprinting
    * assessment of Layer 3 protocol support on hosts
    * open UDP and TCP port detection
    * security event analysis and reporting
    * password recovery
    * development of IDS signatures

**51. Match the network security testing tool with the correct function. (Not all options are used.)**
    * **Nmap:**
    * **Wireshark:**
    * **Nessus:**
        * a) Packet capture and protocol analysis
        * b) Vulnerability scanning
        * c) Port scanning and operating system detection


**52. Which two means can be used to try to bypass the management of mobile devices? (Choose two.)**
    * using a fuzzer
    * rooting
    * jailbreaking
    * packet sniffing
    * using a Trojan Horse

**53. Match the type of cyberattackers to the description. (Not all options are used.)**
    * **Script kiddies:**
    * **Hacktivists:**
    * **Nation-state actors:** 
    * **Insider threats:**

        * a) Highly skilled attackers sponsored by governments.
        * b) Use existing hacking tools to launch attacks.
        * c) Individuals within an organization who exploit their access.
        * d) Launch attacks for political or social reasons.
 

**54. What is a benefit of having users or remote employees use a VPN to connect to the existing network rather than growing the network infrastructure?**
    * security
    * scalability
    * cost savings
    * compatibility

**55. What is a difference between symmetric and asymmetric encryption algorithms?**
    * Symmetric algorithms are typically hundreds to thousands of times slower than asymmetric algorithms.
    * Symmetric encryption algorithms are used to authenticate secure communications. Asymmetric encryption algorithms are used to repudiate messages.
    * Symmetric encryption algorithms are used to encrypt data. Asymmetric encryption algorithms are used to decrypt data.
    * Symmetric encryption algorithms use pre-shared keys. Asymmetric encryption algorithms use different keys to encrypt and decrypt data.

**56. What technology allows users to verify the identity of a website and to trust code that is downloaded from the Internet?**
    * asymmetric key algorithm
    * digital signature
    * encryption
    * hash algorithm

**57. Which two statements correctly describe certificate classes used in the PKI? (Choose two.)**
    * A class 0 certificate is for testing purposes.
    * A class 0 certificate is more trusted than a class 1 certificate.
    * The lower the class number, the more trusted the certificate.
    * A class 5 certificate is for users with a focus on verification of email.
    * A class 4 certificate is for online business transactions between companies.

**58. What is the standard for a public key infrastructure to manage digital certificates?**
    * PKI
    * NIST-SP800
    * x.503
    * x.509

**59. Which two statements describe remote access VPNs? (Choose two.)**
    * Remote access VPNs are used to connect entire networks, such as a branch office to headquarters.
    * End users are not aware that VPNs exists.
    * A leased line is required to implement remote access VPNs.
    * Client software is usually required to be able to access the network.
    * Remote access VPNs support the needs of telecommuters and mobile users.

**60. What are two hashing algorithms used with IPsec AH to guarantee authenticity? (Choose two.)**
    * MD5
    * SHA
    * AES
    * DH
    * RSA

**61. What is the purpose of configuring multiple crypto ACLs when building a VPN connection between remote sites?**
    * By applying the ACL on a public interface, multiple crypto ACLs can be built to prevent public users from connecting to the VPN-enabled router.
    * Multiple crypto ACLs can be configured to deny specific network traffic from crossing a VPN.
    * When multiple combinations of IPsec protection are being chosen, multiple crypto ACLs can define different traffic types.
    * Multiple crypto ACLs can define multiple remote peers for connecting with a VPN-enabled router across the Internet or network.

**62. Refer to the exhibit. An administrator creates three zones (A, B, and C) in an ASA that filters traffic. Traffic originating from Zone A going to Zone C is denied, and traffic originating from Zone B going to Zone C is denied. What is a possible scenario for Zones A, B, and C?**
    * A – DMZ, B – Inside, C – Outside
    * A – Inside, B – DMZ, C – Outside
    * A – Outside, B – Inside, C – DMZ
    * A – DMZ, B – Outside, C – Inside

**63. What are two monitoring tools that capture network traffic and forward it to network monitoring devices? (Choose two.)**
    * SIEM
    * Wireshark
    * SNMP
    * SPAN
    * network tap

**64. What is the IPS detection engine that is included in the SEC license for 4000 Series ISRs?**
    * Security Onion
    * Snort
    * ASDM
    * AMP

















