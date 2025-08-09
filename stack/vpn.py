import pulumi_ibm as ibm
from .config import Config


def create_vpn_server(cfg: Config, vpc, subnet, cert_secrets):
    vpn_security_group = ibm.IsSecurityGroup(
        "vpn-security-group",
        name=f"{cfg.vpc_name}-vpn-sg",
        vpc=vpc.id,
        resource_group=cfg.resource_group_id,
        tags=["pulumi", "security-group", "vpn"],
    )

    ibm.IsSecurityGroupRule(
        "vpn-sg-rule-inbound",
        group=vpn_security_group.id,
        direction="inbound",
        ip_version="ipv4",
        udp={"port_min": 443, "port_max": 443},
        remote="0.0.0.0/0",
    )

    ibm.IsSecurityGroupRule(
        "vpn-sg-rule-outbound",
        group=vpn_security_group.id,
        direction="outbound",
        ip_version="ipv4",
        remote="0.0.0.0/0",
    )

    ibm.IsSecurityGroupRule(
        "vpn-sg-rule-icmp",
        group=vpn_security_group.id,
        direction="inbound",
        ip_version="ipv4",
        icmp={"type": 8, "code": 0},
        remote="0.0.0.0/0",
    )

    vpn_server = ibm.IsVpnServer(
        "vpn-server",
        name=f"{cfg.vpc_name}-vpn-server",
        certificate_crn=cert_secrets["server_secret"].crn,
        client_authentications=[{"method": "certificate", "client_ca_crn": cert_secrets["intermediate_secret"].crn}],
        client_ip_pool=cfg.vpn_client_cidr,
        client_idle_timeout=2800,
        enable_split_tunneling=False,
        port=443,
        protocol="udp",
        subnets=[subnet.id],
        security_groups=[vpn_security_group.id],
        resource_group=cfg.resource_group_id,
        tags=["pulumi", "vpn-server"],
    )

    return vpn_server

