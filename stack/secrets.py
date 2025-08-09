import pulumi_ibm as ibm
from .config import Config


def create_secrets_manager(cfg: Config):
    sm = ibm.ResourceInstance(
        "secrets-manager",
        name=f"{cfg.vpc_name}-secrets-manager",
        service="secrets-manager",
        plan="standard",
        location=cfg.region,
        resource_group_id=cfg.resource_group_id,
        parameters={"allowed_network": "public-and-private"},
        tags=["pulumi", "pki", "secrets-manager"],
    )
    return sm, sm.guid


def create_secret_groups(instance_id):
    ca_group = ibm.SmSecretGroup(
        "ca-secret-group",
        instance_id=instance_id,
        name="pki-ca-certificates",
        description="PKI CA certificates and keys",
    )
    server_group = ibm.SmSecretGroup(
        "server-secret-group",
        instance_id=instance_id,
        name="pki-server-certificates",
        description="PKI server certificates and keys",
    )
    client_group = ibm.SmSecretGroup(
        "client-secret-group",
        instance_id=instance_id,
        name="pki-client-certificates",
        description="PKI client certificates and keys",
    )
    return ca_group, server_group, client_group

