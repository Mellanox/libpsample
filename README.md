# libpsample

This library enables userspace programs to interact with the kernel psample
module.

The library allows to:
 - Get sampled packets.
 - Parse sampled packets
 - List current sample groups
 - Write sampled packets to file

In addition, the library contains an executable named 'psample' that provide
those features in a command line executable.

### The psample Kernel Module
psample is kernel module that allows sampling packets and transferring them to
userspace programs. The psample module is not bound to any specific kernel
subsystem and allows every driver to sample packets. Currently, the tc action
'sample' uses psample for its sampled packets.

The psample module defines sampling 'group', thus allowing several kernel
modules to sample packets in their own channel. In addition, the sampled packets
are sent as a netlink multicast packets, thus allowing several user programs to
get the sampled packets of a certain group.

To configure sampling using tc, one may use the commands:
~~~
 tc qdisc add dev $DEV handle ffff: ingress
 tc filter add dev $DEV parent ffff: matchall skip_hw \
	   action sample rate 12 group 7
~~~

### The psample Executable
In addition to the library, the git contains the psample executable, which
allows a command-line user to get information about the current sample groups
and the sampled packets in those groups.

Basic usage:
~~~
 # to monitor all sampled packets and config events
 psample [-v]

 # to filter sampled packets/config events by group
 psample [-v] --group 6

 # to monitor all sampled packets only
 psample [-v] --no-config

 # to monitor all config events only
 psample [-v] --no-sample

 # to show all current groups
 psample --list-groups

 # to write packets to file
 psample --write psample.pcap

 # to write packets to stdout
 psample --write -
 This option is useful for piping the output to tshark to dissect packets:
 psample --write - | tshark -r - -V
~~~

### Basic Library Usage
An example for the library usage can be seen in the psample executable code,
under `psample_tool/psample.c`

### Further Resources
1. man tc-sample
