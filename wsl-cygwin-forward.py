#!/usr/bin/python3

"""
wsl-forward.py
==============

This utlity sets up IPv4 port-forwarding of SSH port (22) from host to a
running WSL Linux. It is to be run inside a administrative cygwin terminal
session on the Windows host. It is to be run after a WSL instance has been
launched.

The utility depends on the availability of following commands on Windows:

- `id`
- `wsl`
- `netsh`
- `ipconfig`

This utility does the following steps:

- `uname -a`

Check if we are running in a Cygwin terminal

- `id -G`

Check if current terminal session is run in admin mode

- `wsl --user root ifconfig <wsl_intf>`

Parse the output of this command to find out the IP address assigned to
the WSL inner network interface

- `ipconfig`

Parse the output to get the WSL IP address and network mask on the host

- `netsh advfirewall firewall show rule name=all`

Get all the firewall rules and extract all the rules related to ssh_port

- `netsh advfirewall firewall delete rule ...`

Remove all firewall rules extracted in previous command. This is necessary
because each time Windows launches a WSL instance the inner and host IP
addresses may be different. Firewall rules associated with the old IP
address will prevent the port-forwarding of traffic to current IP address.

- `netsh inteface portproxy add v4tov4 ...`

- `netsh advfirewall firewall add rule ...`

These two commands configure port-forwarding and firewall policy that
forwards traffic to WSL ip address and ssh_port into WSL Linux instance.

"""

import argparse
import ipaddress
import re
import sys
import subprocess
from subprocess import PIPE


def run_cmd(cmd_and_args, verbose=False):
    """Execute shell command and capture stdout/stderr"""
    if verbose:
        print(" ".join(cmd_and_args))
    return subprocess.run(cmd_and_args, stdout=PIPE, stderr=PIPE, check=False)


def exit_err(msg, output):
    """Print error and exit"""
    assert output.returncode != 0
    print(f"{msg}: {output.stderr.decode('utf-8')}")
    sys.exit(1)


def must_be_cygwin_nt():
    """Make sure we are in Cygwin"""
    output = run_cmd(["uname", "-a"])
    if output.returncode != 0:
        exit_err("Error in detecting running OS", output)
    output = output.stdout.decode("utf-8")
    if "cygwin_nt" not in output.lower():
        print(f"This script must be run in cygwin: {output}")
        sys.exit(1)


def must_run_administrative_mode():
    """
    Verify we are running in administrative mode. Use command 'id -G'.
    On Windows 'id -G' output containing 114 or 544 means current terminal
    is in admin mode.
    """
    output = run_cmd(["id", "-G"])
    if output.returncode != 0:
        exit_err("Error in detecting admin mode", output)
    output = output.stdout.decode("utf-8")
    if " 114 " in output or " 544 " in output:
        return
    print(f"This script must be run in administrative cygwin: {output}")
    sys.exit(1)


def must_have_exec(execs):
    """Use `which` to verify commands exist"""
    result = {}
    for exe in execs:
        output = run_cmd(["which", exe])
        if output.returncode != 0:
            exit_err(f"Error in locating executable {exe}", output)
        else:
            result[exe] = output.stdout.decode("utf-8").strip()
    if len(result) != len(execs):
        sys.exit(1)
    return result


def must_get_wsl_inner_ip(wsl_intf):
    """
    Get IPv4 addr, mask and brd addr of eth0 of the running Linux WSL instance
    Returns a tuple of (network, addr, brd_addr)
    """
    ipv4_pattern = r"(\d+\.\d+\.\d+\.\d+)"

    # ifconfig parse pattern
    ifconfig_pattern = re.compile(
        f"\\s+inet\\s+{ipv4_pattern}"
        f"\\s+netmask\\s+{ipv4_pattern}"
        f"\\s+broadcast\\s+{ipv4_pattern}"
    )

    output = run_cmd(["wsl", "--user", "root", "ifconfig", wsl_intf])
    if output.returncode != 0:
        exit_err("Error in getting wsl inner ip", output)
    addr_info = None
    for line in output.stdout.decode("utf-8").split("\n"):
        m = re.search(ifconfig_pattern, line)
        if m:
            addr_info = (m.group(1), m.group(2), m.group(3))
            break
    if not addr_info:
        print(f"Cannot find inner ip {output.stdout.decode('utf-8')}")
        sys.exit(1)
    try:
        network = ipaddress.IPv4Network(addr_info[0] + "/" + addr_info[1], strict=False)
        return (network, addr_info[0], addr_info[2])
    except ipaddress.AddressValueError as ex:
        print(f"Parse network {addr_info} error: {ex}")
        sys.exit(1)


def must_get_wsl_adaptor_ip():
    """
    Scan WSL network adaptor IPv4 addresses. Return a dict of network -> addr
    """
    output = run_cmd(["ipconfig"])
    if output.returncode != 0:
        exit_err("ipconfig error", output)
    start_scan = False
    result = {}
    current_addr = None

    ipv4_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    for line in output.stdout.decode("utf-8").split("\n"):
        if not start_scan:
            if "(WSL " in line:
                start_scan = True
            continue
        # scan WSL adaptor addrs
        m = re.search(f"\\s+IPv4 Address.+ {ipv4_pattern}", line)
        if m:
            current_addr = m.group(1)
        m = re.search(f"\\s+Subnet Mask.+ {ipv4_pattern}", line)
        if m:
            assert current_addr, "current_addr not set"
            network = ipaddress.IPv4Network(
                current_addr + "/" + m.group(1), strict=False
            )
            result[network] = current_addr
            current_addr = None
    if not result:
        print(
            "Cannot locate WSL adaptor IPv4 addr in: "
            f"{output.stdout.decode('utf-8')}"
        )
        sys.exit(1)
    return result


def get_ssh_port_rules(ssh_port):
    """Get all rules with LocalPort of SSH_PORT"""
    cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    output = run_cmd(cmd)
    if output.returncode != 0:
        exit_err("Get advfirewall error", output)
    rules = []
    current_rule = {}
    for line in output.stdout.decode("utf-8").split("\n"):
        m = re.search(r"^Rule Name:\s+(\S.+\S+)", line)
        if m:
            if current_rule and current_rule["Counter"] == 4:
                rules.append(current_rule)
            current_rule = {"Name": m.group(1), "Counter": 0}
            continue
        m = re.search(f"^LocalPort:\\s+{ssh_port}", line)
        if m:
            current_rule["Counter"] += 1
            continue
        m = re.search(r"^Protocol:\s+TCP", line)
        if m:
            current_rule["Counter"] += 1
            continue
        m = re.search(r"^Direction:\s+In", line)
        if m:
            current_rule["Counter"] += 1
            continue
        m = re.search(r"^Action:\s+Allow", line)
        if m:
            current_rule["Counter"] += 1
            continue

    if "Name" in current_rule and current_rule["Counter"] == 4:
        rules.append(current_rule)

    return rules


def remove_ssh_port_rules(rules, ssh_port):
    """remote any existing firewall rule"""
    for rule in rules:
        rule_name = rule["Name"]
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "protocol=tcp",
            f"localport={ssh_port}",
        ]
        output = run_cmd(cmd, verbose=True)
        if output.returncode != 0:
            exit_err(f'Remove port firewall allow rule "{rule_name}" failed', output)


def add_forwarding_rules(adaptor_addr, inner_addr, ssh_port):
    """
    Add rules to forward packets from external adaptor address to the WSL inner
    address.
    """
    cmd = [
        "netsh",
        "interface",
        "portproxy",
        "add",
        "v4tov4",
        f"listenaddress={adaptor_addr}",
        f"listenport={ssh_port}",
        f"connectaddress={inner_addr}",
        f"connectport={ssh_port}",
    ]
    output = run_cmd(cmd, verbose=True)
    if output.returncode != 0:
        exit_err("Add port proxy rule failed", output)

    # add port proxy rule for local host. listen on ANY ip address inside WSL
    cmd = [
        "netsh",
        "interface",
        "portproxy",
        "add",
        "v4tov4",
        "listenaddress=0.0.0.0",
        f"listenport={ssh_port}",
        f"connectaddress={inner_addr}",
        f"connectport={ssh_port}",
    ]
    output = run_cmd(cmd, verbose=True)
    if output.returncode != 0:
        exit_err("Add port proxy rule failed", output)

    # add firewall on ssh_port to allow TCP traffic
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name='open wsl ssh port'",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        f"localport={ssh_port}",
    ]
    output = run_cmd(cmd, verbose=True)
    if output.returncode != 0:
        exit_err("Add port firewall allow rule failed", output)


def main():
    """main"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", default=22, help="SSH port, default is 22")
    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="WSL inner eth interface, default is eth0",
    )
    args = parser.parse_args()

    must_be_cygwin_nt()
    must_run_administrative_mode()
    result = must_have_exec(["netsh", "wsl"])
    print(result)
    addr_info = must_get_wsl_inner_ip(args.interface)
    print(addr_info)
    adaptor_info = must_get_wsl_adaptor_ip()
    print(adaptor_info)

    # check inner network matches WSL adaptor
    if addr_info[0] not in adaptor_info:
        print(f"Cannot find matching WSL adaptor network{addr_info}")
        sys.exit(1)

    # check if there are already advfirewall rules for SSH_PORT. If so we
    # may want to remove them
    rules = get_ssh_port_rules(args.port)
    if rules:
        for rule in rules:
            print("Rule Name: " + rule["Name"])
        answer = input("Do you want to remove existing rules? (Y/N) ")
        if answer.lower() == "y":
            remove_ssh_port_rules(rules, args.port)
        else:
            print("Keep existing rules")

    adaptor_addr = adaptor_info[addr_info[0]]
    inner_addr = addr_info[1]

    add_forwarding_rules(adaptor_addr, inner_addr, args.port)


if __name__ == "__main__":
    main()
