import pulumi
import pulumi_ibm as ibm
from .config import Config


def create_network(cfg: Config):
    vpc = ibm.IsVpc(
        "vpc",
        name=cfg.vpc_name,
        resource_group=cfg.resource_group_id,
        address_prefix_management="manual",
        tags=["pulumi", "pki", "vpn"],
    )

    # Ensure address prefixes exist for each zone where we create subnets
    prefix_primary = ibm.IsVpcAddressPrefix(
        "vpc-prefix-zone1",
        name=f"{cfg.vpc_name}-prefix-1",
        vpc=vpc.id,
        zone=f"{cfg.region}-1",
        cidr=cfg.subnet_cidr,
    )

    subnet = ibm.IsSubnet(
        "subnet",
        name=f"{cfg.vpc_name}-subnet",
        vpc=vpc.id,
        zone=f"{cfg.region}-1",
        ipv4_cidr_block=cfg.subnet_cidr,
        resource_group=cfg.resource_group_id,
        tags=["pulumi", "subnet", "vpn"],
        opts=pulumi.ResourceOptions(depends_on=[prefix_primary]),
    )

    second_subnet = None
    if cfg.ha_enabled:
        prefix_secondary = ibm.IsVpcAddressPrefix(
            "vpc-prefix-zone2",
            name=f"{cfg.vpc_name}-prefix-2",
            vpc=vpc.id,
            zone=f"{cfg.region}-2",
            cidr=cfg.second_subnet_cidr,
        )
        second_subnet = ibm.IsSubnet(
            "subnet-ha",
            name=f"{cfg.vpc_name}-subnet-ha",
            vpc=vpc.id,
            zone=f"{cfg.region}-2",
            ipv4_cidr_block=cfg.second_subnet_cidr,
            resource_group=cfg.resource_group_id,
            tags=["pulumi", "subnet", "vpn", "ha"],
            opts=pulumi.ResourceOptions(depends_on=[prefix_secondary]),
        )

    return vpc, subnet, second_subnet

