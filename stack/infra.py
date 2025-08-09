import pulumi_ibm as ibm
from .config import Config


def create_network(cfg: Config):
    vpc = ibm.IsVpc(
        "vpc",
        name=cfg.vpc_name,
        resource_group=cfg.resource_group_id,
        tags=["pulumi", "pki", "vpn"],
    )

    subnet = ibm.IsSubnet(
        "subnet",
        name=f"{cfg.vpc_name}-subnet",
        vpc=vpc.id,
        zone=f"{cfg.region}-1",
        ipv4_cidr_block=cfg.subnet_cidr,
        resource_group=cfg.resource_group_id,
        tags=["pulumi", "subnet", "vpn"],
    )

    return vpc, subnet

