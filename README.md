# Opensource NAC Research

---

## Index

- [Contributors](#contributors)
- [Project Scope](#project-scope)
- [Abstract](#abstract)
- [Studied Technology and Headlines](#studied-technology-and-headlines)
  - [Packetfence](#packetfence)
    - [802.1X Support](#8021x-support)
    - [Registration of Devices](#registration-of-devices)
    - [Wireless Integration](#wireless-integration)
    - [Detection of Abnormal Network Activities](#detection-of-abnormal-network-activities)
    - [Windows Management Instrumentation (WMI)](#windows-management-instrumentation-wmi)
    - [Proactive Vulnerability Scans](#proactive-vulnerability-scans)
    - [Security Agents](#security-agents)
    - [Remediation Through a Captive Portal](#remediation-through-a-captive-portal)
  - [OpenVAS/GVM](#openvasgvm)
- [Tests and Conclusions](#tests-and-conclusions)
- [General Evaluation](#general-issues-with-packetfence)
- [Appendix](#appendix)
- [References](#references)

---

## CONTRIBUTORS

| Name - Surname    |
| :---------------- |
| ARDA ÖZKAL        |
| FATIH MALAKÇI     |
| RUKİYE GÜL ÖZTÜRK |
| SERHAT ERDENER    |

---

## PROJECT SCOPE

This is a research of open source NAC solutions that can be used instead of
commercial counterparts by physically constructing a similar big scale
infrastructure environment. Also testing the chosen open source NAC solution in
this environment.

---

## ABSTRACT

The purpose of this project is establishing an infrastructure that uses an open
source NAC software. Our wish from this system is to scan user devices who wants
to join our network. A "guest zone" should be created for guest users after the
scan and users should be assigned to VLAN's according to their roles/levels.

After the research & development process done by our team we decided to use a
open source project that's actively supported by a community. That's why
`Packetfence` NAC tool is chosen because it allows `OpenVAS/GVM`,
`Windows Management Instrumentation` (_WMI_) complience check for different
operating systems and can be integrated via 802.1x authentication &
authorisation.

After the tests it has been seen that Compliance Check feature is not working as
intended and Packetfence cannot integrate well with the compliance check
softwares available us to use. That's why we decided to conclude the research,
the tests performed and their results have been detailed inside this document.

---

## Studied Technology and Headlines

The softwares which will be used for open source NAC solution are detailed
below.

### Packetfence

`PacketFence` is a fully supported, trusted, Free and Open Source network access
control (NAC) solution. Boasting an impressive feature set including a
captive-portal for registration and remediation, centralized wired and wireless
management, 802.1X support, layer-2 isolation of problematic devices,
integration with the `Snort` IDS and the `Nessus` vulnerability scanner;
`PacketFence` can be used to effectively secure networks - from small to very
large heterogeneous networks.

![Packetfence](images/packetfence.png)

#### 802.1X Support

Wireless and wired 802.1X is supported through a `FreeRADIUS` module which is
included in `PacketFence`. PEAP-TLS, EAP-PEAP and many more EAP mechanisms can
be used.

#### Registration of Devices

`PacketFence` supports an optional registration mechanism similar to "captive
portal" solutions. Contrary to most captive portal solutions, `PacketFence`
remembers users who previously registered and will automatically give them
access without another authentication. Of course, this is configurable. An
Acceptable Use Policy can be specified such that users cannot enable network
access without first accepting it.

#### Wireless Integration

`PacketFence` integrates perfectly with wireless networks through a `FreeRADIUS`
module. This allows you to secure your wired and wireless networks the same way
using the same user database and using the same captive portal, providing a
consistent user experience. Mixing access points (AP) vendors and wireless
controllers is supported.

#### Detection of Abnormal Network Activities

Abnormal network activities (computer virus, worms, spyware, traffic denied by
establishment policy, etc.) can be detected using local and remote `Snort`,
`Suricata` or commercial sensors. Content inspection is also possible with
`Suricata`, and can be combined with malware hash databases such as
`OPSWAT Metadefender`. Beyond simple detection, `PacketFence` layers its own
alerting and suppression mechanism on each alert type. A set of configurable
actions for each violation is available to administrators.

#### Windows Management Instrumentation (WMI)

`WMI` support in `PacketFence` allows an administrator to perform audits,
execute commands and even more on any domain-joined Windows computers. For
example, `PacketFence` can verify if some unauthorized software are installed
and/or running before granting network access.

#### Proactive Vulnerability Scans

`Nessus` or `OpenVAS` vulnerability scans can be performed upon registration,
scheduled or on an ad-hoc basis. `PacketFence` correlates the `Nessus`/`OpenVAS`
vulnerability ID's of each scan to the violation configuration, returning
content specific web pages about which vulnerability the host may have.

#### Security Agents

`PacketFence` integrates with security agent solutions such as
`OPSWAT Metadefender Endpoint Management`, `Symantec SEPM` and others.
`PacketFence` can make sure the agent is always installed before granting
network access. It can also check the endpoint's posture and isolate it from any
other endpoints if non-compliant.

#### Remediation Through a Captive Portal

Once trapped, all network traffic is terminated by the `PacketFence` system.
Based on the nodes current status (unregistered, open violation, etc), the user
is redirected to the appropriate URL. In the case of a violation, the user will
be presented with instructions for the particular situation he/she is in,
reducing costly help desk intervention.

#### Isolation of Problematic Devices

`PacketFence` supports several isolation techniques, including VLAN isolation
with VoIP support (even in heterogeneous environments) for multiple switch
vendors [1].

### OpenVAS/GVM

`OpenVAS` is a full-featured vulnerability scanner. Its capabilities include
unauthenticated testing, authenticated testing, various high level and low level
Internet and industrial protocols, performance tuning for large-scale scans and
a powerful internal programming language to implement any type of vulnerability
test.

The scanner is developed and maintained by Greenbone Networks since 2009. The
works are contributed as Open Source to the community under the GNU General
Public License (GNU GPL) [2].

---

## Tests and Conclusions

`Packetfence` supports 4 different Compliance Check software, The free/open
source ones are marked below.

- `OpenVAS/GVM` - _free/open source_
- `WMI` (Windows Management Instrumentation) - _free of charge_
- `Rapid7`
- `Nessus` (and `Nessus 6`)

We will study `openVAS/GVM` and `WMI` because others are commercial products
which we will not cover in this study.


### OpenVAS/GVM

OpenVAS/GVM is a FOSS vulnerability scanner maintained by Greenbone Networks GmbH.

It has been renamed to GVM as of version 10, released in 2017.

#### Setup Process

- We did our initial tests with [OpenVAS 9 on Debian Buster repos](https://packages.debian.org/buster/openvas).

- As we found out that this version was deprecated and couldn't easily get gcf updates due to the [HTTP sync servers shutting down](https://community.greenbone.net/t/shutting-down-gcf-http-download/5339), we decided to use a newer, maintained version.

- Out of the 3 alternatives of GVM-10, GVM-11 and GVM-20, we chose to continue with GVM-20 as [the other two had their support period end as of 2021](https://community.greenbone.net/t/gvm-20-08-stable-initial-release-2020-08-12/6312). We compiled and configured it, and tested the functionality.

- We noticed issues with scans not starting properly after trying to integrate GVM-20 to PacketFence. We found an [open Github issue](https://github.com/inverse-inc/packetfence/issues/5791) on the issue. We thoroughly investigated this error and determined it to be related to [a breaking change in GVM-20](https://docs.greenbone.net/API/GMP/gmp-20.08.html#changes). This change requires supplying a port list to create a scan target (which are created for devices on the network).

**Error on GVM-20:**

```
WARN: [mac:[undef]] There was an error creating scan target named 160008315756ae61600083157.5xxxx, here's the output: <create_target_response status_text="One of PORT_LIST and PORT_RANGE are required" status="400"></create_target_response> (pf::scan::openvas::createTarget)
```

*(Scan target creation fails due to missing "PORT\_LIST" or "PORT\_RANGE".)*

- As a solution, we added support to Packetfence to manually specify a port list UUID. We've sent this as a PR to the [PacketFence project](https://github.com/inverse-inc/packetfence/pull/6082), but are yet to receive a response.

![Port list textbox](https://camo.githubusercontent.com/efa7dd3b2991ed6a9f8a82071d78feb9d46cdab1208e5fb66e0d479e341a0ef5/68747470733a2f2f656c6978692e72652f692f6c743367633373632e706e67)

*(A textbox was added to specify a "PORT\_LIST" UUID under the other UUID textboxes.)*

- We set up a physical environment to test entegration of real devices with our network team.

#### Test Process

- We joined the AD domain on two Linux machines, and set up 802.1x EAP accordingly. These devices were then connected to a PacketFence-integrated switch using an ethernet cable.

- We noticed that scans were created repeatedly while machines were connected on Packetfence and GVM logs. We also noticed that PacketFence didn't use the scan result from GVM.

**Scans being created repeatedly:**

```
Feb  2 15:02:57 itpf pfqueue: pfqueue(14350) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan task named 161226737754ca811612267377.41867 (pf::scan::openvas::createTask)
Feb  2 15:02:57 itpf pfqueue: pfqueue(14350) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226737754ca811612267377.41867 successfully created with id: 3af5b1f1-f5fc-48b5-ac9c-084363bee4cb (pf::scan::openvas::createTask)
Feb  2 15:02:57 itpf pfqueue: pfqueue(14350) INFO: [mac:re:da:ct:ed:ma:ca] Starting scan task named 161226737754ca811612267377.41867 (pf::scan::openvas::startTask)
Feb  2 15:02:57 itpf pfqueue: pfqueue(14350) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226737754ca811612267377.41867 successfully started (pf::scan::openvas::startTask)
Feb  2 15:03:35 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan target named 161226741454ca811612267414.99439 for host 172.22.46.150 (pf::scan::openvas::createTarget)
Feb  2 15:03:37 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Scan target named 161226741454ca811612267414.99439 successfully created with id: 59e3551c-cd28-46cb-b88c-6fcd37b8be0e (pf::scan::openvas::createTarget)
Feb  2 15:03:37 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan task named 161226741454ca811612267414.99439 (pf::scan::openvas::createTask)
Feb  2 15:03:38 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226741454ca811612267414.99439 successfully created with id: fc1593ad-81b6-413d-9046-23093c112075 (pf::scan::openvas::createTask)
Feb  2 15:03:38 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Starting scan task named 161226741454ca811612267414.99439 (pf::scan::openvas::startTask)
Feb  2 15:03:38 itpf pfqueue: pfqueue(14494) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226741454ca811612267414.99439 successfully started (pf::scan::openvas::startTask)
Feb  2 15:03:47 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan target named 161226742712ca811612267427.76932 for host 172.22.46.150 (pf::scan::openvas::createTarget)
Feb  2 15:03:47 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Scan target named 161226742712ca811612267427.76932 successfully created with id: 93560924-6eea-4287-bf5d-2c3dff276fc7 (pf::scan::openvas::createTarget)
Feb  2 15:03:47 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan task named 161226742712ca811612267427.76932 (pf::scan::openvas::createTask)
Feb  2 15:03:48 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226742712ca811612267427.76932 successfully created with id: 92f484b4-772a-488b-952f-fdbd8e909159 (pf::scan::openvas::createTask)
Feb  2 15:03:48 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Starting scan task named 161226742712ca811612267427.76932 (pf::scan::openvas::startTask)
Feb  2 15:03:48 itpf pfqueue: pfqueue(14543) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226742712ca811612267427.76932 successfully started (pf::scan::openvas::startTask)
Feb  2 15:04:02 itpf pfqueue: pfqueue(14598) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan target named 161226744223ca811612267442.80235 for host 172.22.46.150 (pf::scan::openvas::createTarget)
Feb  2 15:04:03 itpf pfqueue: pfqueue(14598) INFO: [mac:re:da:ct:ed:ma:ca] Scan target named 161226744223ca811612267442.80235 successfully created with id: 37fadd42-8653-4f29-b1c8-e064f03e09ab (pf::scan::openvas::createTarget)
Feb  2 15:04:03 itpf pfqueue: pfqueue(14598) INFO: [mac:re:da:ct:ed:ma:ca] Creating a new scan task named 161226744223ca811612267442.80235 (pf::scan::openvas::createTask)
Feb  2 15:04:03 itpf pfqueue: pfqueue(14598) INFO: [mac:re:da:ct:ed:ma:ca] Scan task named 161226744223ca811612267442.80235 successfully created with id: d483fbc3-dc5c-4eaa-8930-345f04b72f6b (pf::scan::openvas::createTask)
```

*(Scans are being created over and over for a machine, even though the MAC address and IP are identical.)*

- We reviewed PacketFence code and logs. The last warning we saw before the scan failed was related to an SQL query failing due to "report\_id" field being empty. We searched through Github issues and found one instance of it being mentioned on [an issue about WMI scans not working](https://github.com/inverse-inc/packetfence/issues/5877), but being dismissed as being unrelated to the actual issue. We've observed that while this field is required, it is not provided by any Compliance Check provider.

**Warning related to the missing "report\_id" field:** 

```
packetfence.log-20210203:Feb  2 15:04:33 itpf pfqueue: pfqueue(14725) WARN: [mac:re:da:ct:ed:ma:ca] Warning: 1048: Column 'report_id' cannot be null (pf::dal::db_execute)
```

*(PacketFence code is giving out a warning as "report\_id" field is null.)*

```
packetfence.log-20210219:Feb 18 13:38:27 itpf pfqueue: pfqueue(8556) TRACE: [mac:re:da:ct:ed:ma:cb] preparing statement query INSERT INTO `scan` ( `id`, `ip`, `mac`, `report_id`, `start_date`, `status`, `tenant_id`, `type`, `update_date`)
 VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ? ) with bind (16136447074bffc, 172.22.46.68, 172.22.46.68, NULL, 2021-02-18 13:38:27, new, 1, wmi, 0000-00-00 00:00:00) at /usr/local/pf/lib/pf/dal.pm line 1136.
```

*("report\_id" field is "NULL" on empty on a prepared database statement.)*

**Code related to this issue (`lib/pf/scan.pm`):**

```perl
sub statusReportSyncToDb {
    my ( $self ) = @_;
    my $logger = get_logger();
    my ($status, $rows) = pf::dal::scan->update_items(
        -set => {
            status => $self->{_status},
            report_id => $self->{_reportId},
        },
        -where => {
            id => $self->{'_id'}
        }
    );
    if (is_error($status)) {
        return $FALSE;
    }
    return $rows ? $TRUE : $FALSE;
}
```

*(The data provided on `_reportId` is being attempted to be added to the database.)*

```
[root@itpf pf]# grep -r "_reportId"
scan.pm:            report_id => $self->{_reportId},
```

*(`_reportId` is not used anywhere else in the code.)*

```
[root@itpf pf]# grep -r "_status"
[...]
scan/nessus.pm:            '_status'   => undef,
scan/nessus.pm:    $self->{'_status'} = $STATUS_STARTED;
scan/nessus6.pm:            '_status'      => undef,
scan/nessus6.pm:    $self->{'_status'} = $pf::scan::STATUS_STARTED;
scan/nessus6.pm:    while ($nessus->get_scan_status(scan_id => $scan_id->{id}) ne 'completed') {
scan/nessus6.pm:    while ($nessus->get_scan_export_status(scan_id => $scan_id->{id},file_id => $file_id) ne 'ready') {
scan/wmi.pm:            '_status'   => undef,
scan/openvas.pm.bak:            '_status'           => undef,
scan/openvas.pm.bak:        $self->{'_status'} = $STATUS_STARTED;
scan/openvas.pm:            '_status'           => undef,
scan/openvas.pm:        $self->{'_status'} = $STATUS_STARTED;
[...]
```

*(In comparison, `_status` (which is on the line right above `_reportId`), is being used by all Compliance Check providers.)*

### WMI

Windows Management Instrumentation comes built into the Windows operating system, and allows us to query a number of system properties.

As it requires a user with specific permissions to connect to the machine, it is only viable on machines that have joined an AD domain. [TODO: wording]

#### Setup Process

- We gave an AD user "Remote Management" permissions, and added it to PacketFence for WMI.

- We joined the AD domain on a Windows 10 Pro machine.

#### Test Process

- We set up 802.1x EAP on the Windows 10 machine, and connected it to a PacketFence-integrated switch using an ethernet cable.

- While observing PacketFence, we noticed that scans sometimes didn't start properly, sometimes repeatedly started, and sometimes failed to succeed upon starting. We also observed that the machine disconnected from the network a couple minutes after being plugged in. We also observed "NT\_STATUS\_IO\_TIMEOUT" and "NT\_STATUS\_ACCESS\_DENIED" errors on the logs.

**Repeatedly starting:**

```
Feb 18 14:00:13 itpf pfqueue: pfqueue(13479) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:00:27 itpf pfqueue: pfqueue(13541) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:00:42 itpf pfqueue: pfqueue(13591) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:00:58 itpf pfqueue: pfqueue(13649) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:04:13 itpf pfqueue: pfqueue(14391) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:04:28 itpf pfqueue: pfqueue(14452) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
Feb 18 14:04:43 itpf pfqueue: pfqueue(14502) DEBUG: [mac:re:da:ct:ed:ma:cb] Instantiating a new pf::scan::wmi scanning object (pf::scan::wmi::new)
```

*(Tests are started repeatedly every few seconds for the same MAC address.)*

**"NT\_STATUS\_IO\_TIMEOUT" and "NT\_STATUS\_ACCESS\_DENIED" errors:**

```
Feb 18 13:38:39 itpf packetfence_httpd.webservices: httpd.webservices(2137) INFO: [mac:re:da:ct:ed:ma:cb] New ID generated: 161364471977bffc (pf::util::generate_id)
Feb 18 13:38:39 itpf packetfence_httpd.webservices: httpd.webservices(2137) ERROR: [mac:re:da:ct:ed:ma:cb] Error rule wmi rule 'Software_Installed': NTSTATUS: NT_STATUS_ACCESS_DENIED - Access denied
 (pf::scan::wmi::rules::test)
Feb 18 13:38:39 itpf packetfence_httpd.webservices: httpd.webservices(2137) WARN: [mac:re:da:ct:ed:ma:cb] WMI scan didnt start (pf::scan::wmi::startScan)
Feb 18 13:38:39 itpf packetfence_httpd.webservices: httpd.webservices(2137) INFO: [mac:re:da:ct:ed:ma:cb] security_event 1200005 closed for re:da:ct:ed:ma:cb (pf::security_event::security_event_close)
```

*(Some tests fail with an "NT_STATUS_ACCESS_DENIED" error.)*

```
Feb 18 16:01:22 itpf pfqueue: pfqueue(8160) ERROR: [mac:re:da:ct:ed:ma:cb] Error rule wmi rule 'Antivirus': NTSTATUS: NT_STATUS_IO_TIMEOUT - NT_STATUS_IO_TIMEOUT
 (pf::scan::wmi::rules::test)
Feb 18 16:01:22 itpf pfqueue: pfqueue(8160) WARN: [mac:re:da:ct:ed:ma:cb] WMI scan didnt start (pf::scan::wmi::startScan)
```

*(Some tests fail with an "NT_STATUS_IO_TIMEOUT" error.)*

- We've observed that using "wmic" with identical settings on CLI led to tests succeeding, even though they failed in PacketFence.

### Fingerbank

In addition to the previously mentioned Compliance Check methods, Packetfence supports Fingerbank.

Fingerbank is developed by Inverse Inc, the company behind Packetfence.

It is used to determine system and hardware features such as machine type and operating system based on DHCP fingerprints. At the time of writing, it is free to use up to 300 requests per hour.

While Fingerbank is quite successful at detecting things like operating systems, it doesn't have much success identifying individual Linux distributions. In addition to this, we issues like a linux computer being classified as a "set top box" in our tests.

### General Issues with PacketFence

- We faced issues with scans starting repeatedly and throwing "report\_id" warnings on both Compliance Check providers.
- We had no success with assigning a VLAN to a user based on their AD roles after a scan. While this is possible during initial PacketFence registration, it is not possible to dynamically recalculate VLAN from AD credentials after a scan. It may have been possible to scan before a registration and as such be able to achieve this behavior, however we cannot test this as the compliance check system does not work as intended.

---

## Appendix

[Install Guide](installation-guide.md)

---

## References

[1] https://www.packetfence.org/ \
[2] https://www.openvas.org/ \
[3] https://packages.debian.org/buster/openvas \
[4] https://community.greenbone.net/t/shutting-down-gcf-http-download/5339 \
[5] https://community.greenbone.net/t/gvm-20-08-stable-initial-release-2020-08-12/6312 \
[6] https://github.com/inverse-inc/packetfence/issues/5791 \
[7] https://docs.greenbone.net/API/GMP/gmp-20.08.html#changes \
[8] https://github.com/inverse-inc/packetfence/pull/6082 \
[9] https://github.com/inverse-inc/packetfence/issues/5877

---









