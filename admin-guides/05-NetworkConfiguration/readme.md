# Network configuration

## Introduction

Dell Switches (in this example we will talk about S5212F-ON) are relative simple to configure - via SSH. In our examples we will talk about two configurations - Universal and Advanced. For simplicity we will assume only Converged setup, where VMs,Management and Storage traffic will be handled with the same network adapter.

This network configuration also assumes, you are using NetworkATC without any overrides. Therefore VLANs for SMB Direct traffic will be configured as 711-718. It will also assume, that Management VLAN is configured as Access (native). In this example is Management VLAN 700 (but can be adjusted). For tenant VMs there is an example with VLANs 200-210.

This is simplified guide, therefore there is no configuration for SDN.

### Universal Configuration

This config is designed to be bulletproof, and universal. It assumes aggregate switches connected 10/25Gbps ports. It also does not matter if someone will connect some servers NIC Port1 to TOR1 and some to TOR2. As result, VLTi connection can host SMB Direct communication (as if connected correctly, there would be zero traffic, but can be quite utilized if half of servers are connected Port1 <-> TOR2 / Port2 <-> TOR1). Since there is enough capacity, TOR will allow all storage VLANs to communicate on both switches.

* [TOR1- S5212F-ON Universal Configuration](./media/S5212F-ON-TOR2-Universal.cfg)
* [TOR2- S5212F-ON Universal Configuration](./media/S5212F-ON-TOR2-Universal.cfg)

![](./media/networkschema01.png)

### Advanced Configuration

This configuration assumes you/customer is using 100/200Gbps ports in aggregate switches. As S5212F has 3x100Gbps ports, two will be used for North-South communication and only one 100Gbps connection will be for East-West (as if not connected correctly, host will not communicate as odd VLANs are available only on TOR1 and even VLANs are on TOR2). The only traffic that could use VLTi is from VMs and it will flow only if one TOR switch will loose connectivity to Aggregate switches. On the picture are four ports connected (two NICs), but it also can be just one NIC (two ports).

* [TOR1- S5212F-ON Advanced Configuration](./media/S5212F-ON-TOR2-Advanced.cfg)
* [TOR2- S5212F-ON Advanced Configuration](./media/S5212F-ON-TOR2-Advanced.cfg)


![](./media/networkschema02.png)

## Configuring the switch

Switches can be managed with SSH with default username/password admin/admin. You can simply open PowerShell and type **ssh admin@IPADDRESS** to connect to switch.

```config
 ssh admin@IPADDRESS
 
```

![](./media/powershell01.png)

There are just few things you need to know and it is how to enter configuration mode - command **configure terminal**, or just **conf**

```config
configure terminal

```
 
![](./media/powershell02.png)

To display running configuration, you have to exit from config mode by typing **exit** and then you can type **show running-configuration** to display configuration.

```config
exit
show running-configuration
 
```

![](./media/powershell03.png)

In case you don't like holding key to display entire configuration, you can type  **show running-configuration | no-more**

```config
show running-configuration | no-more
 
```

To save configuration (so it will not be rewritten after reboot) you need to copy configuration into startup-configuration

```config
copy running-configuration startup-configuration
 
```

