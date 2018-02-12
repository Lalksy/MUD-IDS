# Welcome to Manufacturer Usage Descriptions (MUD)

MUD is a form of IoT security that looks at ways by which manufacturers explain to network deployments what L3/L4 communication patterns they designed their devices to use.

The basic concept makes use of a URL that is poot out by a device using one of several mechanisms, such as DHCP, LLDP, or as part of an 802.1AR certificate in an EAP-TLS/802.1X authentication.  The URL is then resolved to go get a JSON-encoded YANG-based policy.

## What do you get for that?

The goal of MUD is to *reduce* the threat surface on a device to just that of those specific services on specific systems that are expected to communicate with a Thing.

## Contents
This repo contians a tool to emulate an IoT device on a laptop, several sample MUD profiles, sample keys, and the mud controller. **Do not reuse these keys to secure anything important. They are invalid now.**
The controller contains functions that manipulate MUD files, signatures, and do simple mac-based authentication.

## The Good News

 * We're reusing DHCP, EAP-TLS, LLDP, 802.1AR, and HTTPS to do all of this.
 * All of this configures the network and so no new device agents are anticipated.

## Reference
This repo is based on work in http://github.com/elear/mud
See license for more detail.


