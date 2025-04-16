
1.  **Question:** Why are traditional network security perimeters not suitable for the latest consumer-based network endpoint devices?
    * a) These devices are not managed by the corporate IT department.
    * b) These devices pose no risk to security as they are not directly connected to the corporate network.
    * c) These devices connect to the corporate network through public wireless networks.
    * d) These devices are more varied in type and are portable.


2.  **Question:** What two internal LAN elements need to be secured? (Choose two.)
    * a) edge routers
    * b) IP phones
    * c) fiber connections
    * d) switches
    * e) cloud-based hosts

3.  **Question:** What are two examples of traditional host-based security measures? (Choose two.)
    * a) host-based IPS
    * b) NAS
    * c) 802.1X
    * d) antimalware software
    * e) host-based NAC

4.  **Question:** In an 802.1x deployment, which device is a supplicant?
    * a) RADIUS server
    * b) access point
    * c) switch
    * d) end-user station


5.  **Question:** A company implements 802.1X security on the corporate network. A PC is attached to the network but has not authenticated yet. Which 802.1X state is associated with this PC?
    * a) err-disabled
    * b) disabled
    * c) unauthorized
    * d) forwarding


6.  **Question:** An 802.1X client must authenticate before being allowed to pass data traffic onto the network. During the authentication process, between which two devices is the EAP data encapsulated into EAPOL frames? (Choose two.)
    * a) data nonrepudiation server
    * b) authentication server (TACACS)
    * c) supplicant (client)
    * d) authenticator (switch)
    * e) ASA Firewall

7.  **Question:** Which command is used as part of the 802.1X configuration to designate the authentication method that will be used?
    * a) dot1x system-auth-control
    * b) aaa authentication dot1x
    * c) aaa new-model
    * d) dot1x pae authenticator


8.  **Question:** What is involved in an IP address spoofing attack?
    * a) A rogue node replies to an ARP request with its own MAC address indicated for the target IP address.
    * b) Bogus DHCPDISCOVER messages are sent to consume all the available IP addresses on a DHCP server.
    * c) A rogue DHCP server provides false IP configuration parameters to legitimate DHCP clients.
    * d) A legitimate network IP address is hijacked by a rogue node.


9.  **Question:** At which layer of the OSI model does Spanning Tree Protocol operate?
    * a) Layer 1
    * b) Layer 2
    * c) Layer 3
    * d) Layer 4
    

10. **Question:** A network administrator uses the spanning-tree loopguard default global configuration command to enable Loop Guard on switches. What components in a LAN are protected with Loop Guard?
    * a) All Root Guard enabled ports.
    * b) All PortFast enabled ports.
    * c) All point-to-point links between switches.
    * d) All BPDU Guard enabled ports.
    

11. **Question:** Which procedure is recommended to mitigate the chances of ARP spoofing?
    * a) Enable DHCP snooping on selected VLANs.
    * b) Enable IP Source Guard on trusted ports.
    * c) Enable DAI on the management VLAN.
    * d) Enable port security globally.
    

12. **Question:** Which two ports can send and receive Layer 2 traffic from a community port on a PVLAN? (Choose two.)
    * a) community ports belonging to other communities
    * b) promiscuous ports
    * c) isolated ports within the same community
    * d) PVLAN edge protected ports
    * e) community ports belonging to the same community

13. **Question:** Which protocol should be used to mitigate the vulnerability of using Telnet to remotely manage network devices?
    * a) SNMP
    * b) TFTP
    * c) SSH
    * d) SCP
    

14. **Question:** How can DHCP spoofing attacks be mitigated?
    * a) by disabling DTP negotiations on nontrunking ports
    * b) by implementing port security
    * c) by the application of the ip verify source command to untrusted ports​
    * d) by implementing DHCP snooping on trusted ports
    

15. **Question:** Refer to the exhibit. : 

´´´cisco
SWC# show port-security interface fa0/2
Port Security                      : Enabled
Port Status                        : Secure-up
Violation Mode                     : Shutdown
Aging Time                         : 0 mins
Aging Type                         : Absolute
SecureStatic Address Aging          : Disabled
Maximum MAC Addresses              : 3
Total MAC Addresses                : 1
Configured MAC Addresses           : 1
Sticky MAC Addresses               : 0
Last Source Address:Vlan           : 00E0.F7B0.086E:99
Security Violation Count           : 0
´´´

The network administrator is configuring the port security feature on switch SWC. The administrator issued the command show port-security interface fa 0/2 to verify the configuration. What can be concluded from the output that is shown? (Choose three.)
    * a) Three security violations have been detected on this interface.
    * b) This port is currently up.
    * c) The port is configured as a trunk link.
    * d) Security violations will cause this port to shut down immediately.
    * e) There is no device currently connected to this port.
    * f) The switch port mode for this interface is access mode.

16. **Question:** Two devices that are connected to the same switch need to be totally isolated from one another. Which Cisco switch security feature will provide this isolation?
    * a) PVLAN Edge
    * b) DTP
    * c) SPAN
    * d) BPDU guard


17. **Question:** What is the behavior of a switch as a result of a successful CAM table attack?
    * a) The switch will drop all received frames.
    * b) The switch interfaces will transition to the error-disabled state.
    * c) The switch will forward all received frames to all other ports.
    * d) The switch will shut down.


18. **Question:** Which protocol defines port-based authentication to restrict unauthorized hosts from connecting to the LAN through publicly accessible switch ports?
    * a) RADIUS
    * b) TACACS+
    * c) 802.1x
    * d) SSH


19. **Question:** What device is considered a supplicant during the 802.1X authentication process?
    * a) the router that is serving as the default gateway
    * b) the authentication server that is performing client authentication
    * c) the client that is requesting authentication
    * d) the switch that is controlling network access


20. **Question:** Which term describes the role of a Cisco switch in the 802.1X port-based access control?
    * a) agent
    * b) supplicant
    * c) authenticator
    * d) authentication server


21. **Question:** What type of data does the DLP feature of Cisco Email Security Appliance scan in order to prevent customer data from being leaked outside of the company?
    * a) inbound messages
    * b) outbound messages
    * c) messages stored on a client device
    * d) messages stored on the email server


22. **Question:** What is the goal of the Cisco NAC framework and the Cisco NAC appliance?
    * a) to ensure that only hosts that are authenticated and have had their security posture examined and approved are permitted onto the network
    * b) to monitor data from the company to the ISP in order to build a real-time database of current spam threats from both internal and external sources
    * c) to provide anti-malware scanning at the network perimeter for both authenticated and non-authenticated devices
    * d) to provide protection against a wide variety of web-based threats, including adware, phishing attacks, Trojan horses, and worms


23. **Question:** Which Cisco solution helps prevent MAC and IP address spoofing attacks?
    * a) Port Security
    * b) DHCP Snooping
    * c) IP Source Guard
    * d) Dynamic ARP Inspection


24. **Question:** What Layer 2 attack is mitigated by disabling Dynamic Trunking Protocol?
    * a) VLAN hopping
    * b) DHCP spoofing
    * c) ARP poisoning
    * d) ARP spoofing


25. **Question:** What is the result of a DHCP starvation attack?
    * a) Legitimate clients are unable to lease IP addresses.
    * b) Clients receive IP address assignments from a rogue DHCP server.
    * c) The attacker provides incorrect DNS and default gateway information to clients.
    * d) The IP addresses assigned to legitimate clients are hijacked.


26. **Question:** A network administrator is configuring DAI on a switch with the command ip arp inspection validate dst-mac. What is the purpose of this configuration command?
    * a) to check the destination MAC address in the Ethernet header against the MAC address table
    * b) to check the destination MAC address in the Ethernet header against the user-configured ARP ACLs
    * c) to check the destination MAC address in the Ethernet header against the target MAC address in the ARP body
    * d) to check the destination MAC address in the Ethernet header against the source MAC address in the ARP body
