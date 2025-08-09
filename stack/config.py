from dataclasses import dataclass
import pulumi

@dataclass
class Config:
    region: str
    resource_group_id: str
    vpc_name: str
    subnet_cidr: str
    vpn_client_cidr: str
    pki_common_name: str
    certificate_validity_days: int
    ca_validity_days: int


def load_config() -> Config:
    cfg = pulumi.Config()
    return Config(
        region=cfg.get("region") or "us-south",
        resource_group_id=cfg.require("resource_group_id"),
        vpc_name=cfg.get("vpc_name") or "vpc-pki-vpn",
        subnet_cidr=cfg.get("subnet_cidr") or "10.240.0.0/24",
        vpn_client_cidr=cfg.get("vpn_client_cidr") or "172.16.0.0/16",
        pki_common_name=cfg.get("pki_common_name") or "VPC VPN PKI",
        certificate_validity_days=cfg.get_int("certificate_validity_days") or 365,
        ca_validity_days=cfg.get_int("ca_validity_days") or 3650,
    )

