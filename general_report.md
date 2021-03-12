## Opensource Nac General Research Report

---

## Index

 1. Contributors
 2. Project Scope
 3. Abstract
 4. Studied Technology and Headlines
 5. Tests and Conclusions
 6. General Evaluation
 7. Appendix
 8. References


---

CONTRIBUTORS
---

| NAME-SIRNAME
:--
|
|
| ARDA ÖZKAL
| FATIH MALAKÇI
| RUKİYE GÜL ÖZTÜRK
| SERHAT ERDENER
| ATİLLA DEMİR

---

PROJECT SCOPE
---

This is a research of open source nac solutions that can be used instead of commercial counterparts by physically constructing a similar big scale infrastructure environment. Also testing the chosen open source nac solution in this environment.

---

ABSTRACT
---

The purpose of this project is establishing an infrastructure that uses an open source NAC software. Our wish from this system is to scan user devices who wants to join our network. A "guest zone" should be created for guest users after the scan and users should be assigned to VLAN's according to their roles/levels.

After the research & development process done by our team we decided to use a open source project that's actively supported by a community. That's why Packetfence NAC tool is chosen because it allows OpenVAS/GVM, Windows Management
Instrumentation (WMI) complience check for different operating systems and can be integrated via 802.1x	authentication & authorisation.

After the tests it has been seen that Compliance Check feature is not working as intended and Packetfence cannot integrate well with the compliance  check softwares available us to use. That's why we decided to conclude the research, the tests performed and their results have been detailed inside this document.


---

Studied Technology and Headlines
---

The softwares which will be used for open source NAC solution are detailed below.

## Packetfence

PacketFence is a fully supported, trusted, Free and Open Source network access control (NAC) solution. Boasting an impressive feature set including a captive-portal for registration and remediation, centralized wired and wireless management, 802.1X support, layer-2 isolation of problematic devices, integration with the Snort IDS and the Nessus vulnerability scanner; PacketFence can be used to effectively secure networks - from small to very large heterogeneous networks.

![Packetfence](https://www.packetfence.org/img/components.png)

#### 802.1X Support

Wireless and wired 802.1X is supported through a FreeRADIUS module which is included in PacketFence. PEAP-TLS, EAP-PEAP and many more EAP mechanisms can be used.


#### Registration of Devices
PacketFence supports an optional registration mechanism similar to "captive portal" solutions. Contrary to most captive portal solutions, PacketFence remembers users who previously registered and will automatically give them access without another authentication. Of course, this is configurable. An Acceptable Use Policy can be specified such that users cannot enable network access without first accepting it.

#### Wireless Integration
PacketFence integrates perfectly with wireless networks through a FreeRADIUS module. This allows you to secure your wired and wireless networks the same way using the same user database and using the same captive portal, providing a consistent user experience. Mixing access points (AP) vendors and wireless controllers is supported.

#### Detection of Abnormal Network Activities
Abnormal network activities (computer virus, worms, spyware, traffic denied by establishment policy, etc.) can be detected using local and remote Snort, Suricata or commercial sensors. Content inspection is also possible with Suricata, and can be combined with malware hash databases such as OPSWAT Metadefender. Beyond simple detection, PacketFence layers its own alerting and suppression mechanism on each alert type. A set of configurable actions for each violation is available to administrators.

#### Windows Management Instrumentation (WMI)
WMI support in PacketFence allows an administrator to perform audits, execute commands and even more on any domain-joined Windows computers. For example, PacketFence can verify if some unauthorized software are installed and/or running before granting network access.

#### Proactive Vulnerability Scans
Nessus or OpenVAS vulnerability scans can be performed upon registration, scheduled or on an ad-hoc basis. PacketFence correlates the Nessus/OpenVAS vulnerability ID's of each scan to the violation configuration, returning content specific web pages about which vulnerability the host may have.


#### Security Agents
PacketFence integrates with security agent solutions such as OPSWAT Metadefender Endpoint Management, Symantec SEPM and others. PacketFence can make sure the agent is always installed before granting network access. It can also check the endpoint's posture and isolate it from any other endpoints if non-compliant.

#### Remediation Through a Captive Portal
Once trapped, all network traffic is terminated by the PacketFence system. Based on the nodes current status (unregistered, open violation, etc), the user is redirected to the appropriate URL. In the case of a violation, the user will be presented with instructions for the particular situation he/she is in, reducing costly help desk intervention.

#### Isolation of Problematic Devices
PacketFence supports several isolation techniques, including VLAN isolation with VoIP support (even in heterogeneous environments) for multiple switch vendors.


## OpenVAS/GVM

OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test.

The scanner is developed and maintained by Greenbone Networks since 2009. The works are contributed as Open Source to the community under the GNU General Public License (GNU GPL). [2]



---

Tests and Conclusions
---

Packetfence supports 4 different Compliance Check software, The free/open source ones are marked below.

- OpenVAS/GVM - Free/open source
- WMI (Windows Management Instrumentation) - 	free of charge
- Rapid7
- Nessus (ve Nessus 6)

We will study openVAS/GVM and WMI because others are commercial products which we will not cover in this study.

OpenVAS/GVM
--

OpenVAS/GVM is a full-featured vulnerability scanner that's been developed by Greenbone Networks GmbH.

After 2017 OpenVAS name is changed to GVM as part of the version 10 update.

#### Preperation
