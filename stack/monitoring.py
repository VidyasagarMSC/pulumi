import json
import pulumi
from pulumi_ibm import SmArbitrarySecret


def create_monitoring_tools(instance_id, ca_group, cfg):
    monitoring_payload = json.dumps({
        "monitoring": {
            "enabled": True,
            "alert_threshold_days": 30,
            "check_interval_hours": 24,
            "notification_channels": ["email", "webhook"],
        },
        "certificates": [
            {"name": "vpn-root-ca-certificate", "type": "root_ca", "criticality": "high", "alert_days": [90, 60, 30, 14, 7]},
            {"name": "vpn-intermediate-ca-certificate", "type": "intermediate_ca", "criticality": "high", "alert_days": [60, 30, 14, 7]},
            {"name": "vpn-server-certificate", "type": "server", "criticality": "medium", "alert_days": [30, 14, 7, 3, 1]},
            {"name": "vpn-client-certificate", "type": "client", "criticality": "low", "alert_days": [30, 7, 1]},
        ],
    })

    monitoring = SmArbitrarySecret(
        "cert-monitoring-config",
        instance_id=instance_id,
        name="certificate-expiration-monitoring",
        description="Certificate expiration monitoring and alerting configuration",
        secret_group_id=ca_group.secret_group_id,
        payload=monitoring_payload,
        labels=["monitoring", "certificates", "alerting"],
    )

    secrets_manager_endpoint = pulumi.Output.concat(
        "https://", instance_id, ".", cfg.region, ".secrets-manager.appdomain.cloud"
    )
    certificate_manager_url = pulumi.Output.concat(
        "https://cloud.ibm.com/services/secrets-manager/", instance_id
    )

    tools_payload = pulumi.Output.all(secrets_manager_endpoint, certificate_manager_url).apply(
        lambda vals: json.dumps({
            "tools": {
                "certificate_renewal": {"automated": True, "renewal_threshold_days": 30, "backup_old_certificates": True},
                "certificate_validation": {"chain_validation": True, "crl_checking": False, "ocsp_checking": False},
                "security_scanning": {"weak_key_detection": True, "certificate_transparency_monitoring": False, "vulnerability_scanning": True},
            },
            "endpoints": {
                "secrets_manager": vals[0],
                "api_docs": "https://cloud.ibm.com/apidocs/secrets-manager",
                "certificate_manager": vals[1],
            },
        })
    )

    tools = SmArbitrarySecret(
        "pki-tools-config",
        instance_id=instance_id,
        name="pki-management-tools",
        description="PKI management tools and automation configuration",
        secret_group_id=ca_group.secret_group_id,
        payload=tools_payload,
        labels=["pki-tools", "automation", "management"],
    )

    return monitoring, tools

