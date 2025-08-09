import pulumi
import base64


def export_outputs(cfg, vpc, subnet, secrets_manager, secrets_manager_guid, vpn_server, cert_secrets, client_configs, monitoring, tools):
    # Core infrastructure outputs
    pulumi.export("vpc_id", vpc.id)
    pulumi.export("vpc_name", vpc.name)
    pulumi.export("subnet_id", subnet.id)
    pulumi.export("subnet_cidr", cfg.subnet_cidr)

    # Secrets Manager outputs
    pulumi.export("secrets_manager_guid", secrets_manager_guid)
    pulumi.export("secrets_manager_crn", secrets_manager.crn)
    pulumi.export("secrets_manager_dashboard_url", pulumi.Output.concat("https://cloud.ibm.com/services/secrets-manager/", secrets_manager_guid))

    # VPN server outputs
    pulumi.export("vpn_server_id", vpn_server.id)
    pulumi.export("vpn_server_hostname", vpn_server.hostname)
    pulumi.export("vpn_server_private_ips", vpn_server.private_ips)
    pulumi.export("vpn_server_status", vpn_server.lifecycle_state)

    # Certificate CRNs for programmatic access
    pulumi.export(
        "certificate_crns",
        {
            "root_ca": cert_secrets["ca_secret"].crn,
            "intermediate_ca": cert_secrets["intermediate_secret"].crn,
            "server": cert_secrets["server_secret"].crn,
            "client": cert_secrets["client_secret"].crn,
        },
    )

    # Secret group IDs for organization
    # Note: secret_group fields are not directly passed; using secrets via CRNs

    # Configuration secrets
    pulumi.export(
        "management_configs",
        {
            "client_config": client_configs["client_config_secret"].crn,
            "simple_client_config": client_configs["simple_client_config_secret"].crn,
            "rootca_only_config": client_configs["rootca_only_config_secret"].crn,
            "monitoring_config": monitoring.crn,
            "tools_config": tools.crn,
        },
    )

    # Client configurations for immediate use (base64 encoded for security)
    pulumi.export(
        "client_config_base64",
        client_configs["client_config"].apply(lambda config: base64.b64encode(config.encode("utf-8")).decode("utf-8")),
    )
    pulumi.export(
        "simple_client_config_base64",
        client_configs["simple_client_config"].apply(lambda config: base64.b64encode(config.encode("utf-8")).decode("utf-8")),
    )
    pulumi.export(
        "rootca_only_config_base64",
        client_configs["rootca_only_config"].apply(lambda config: base64.b64encode(config.encode("utf-8")).decode("utf-8")),
    )

    # PKI architecture summary
    pulumi.export(
        "pki_architecture",
        {
            "certificate_hierarchy": "Root CA (4096-bit) -> Intermediate CA (2048-bit) -> End Entities (2048-bit)",
            "validity_periods": {
                "root_ca_days": cfg.ca_validity_days,
                "intermediate_ca_days": cfg.certificate_validity_days * 2,
                "end_entity_days": cfg.certificate_validity_days,
            },
            "security_features": [
                "Three-tier PKI hierarchy",
                "Certificate chain validation",
                "IBM Secrets Manager integration",
                "Automated certificate lifecycle management",
                "Expiration monitoring and alerting",
            ],
            "supported_protocols": ["OpenVPN", "IPSec (with modifications)"],
            "encryption": "AES-256-GCM with RSA key exchange",
        },
    )

    # Resource summary (costs kept in README)
    pulumi.export(
        "resource_summary",
        {
            "resources_created": {
                "vpc": 1,
                "subnet": 1,
                "security_group": 1,
                "security_group_rules": 3,
                "vpn_server": 1,
                "secrets_manager_instance": 1,
                "secret_groups": 3,
                "certificates": 4,
                "configuration_secrets": 3,
            }
        },
    )

