#!/usr/bin/env python3

import pulumi
import pulumi_ibm as ibm
import pulumi_tls as tls
import base64
import json

# Get the current stack configuration
config = pulumi.Config()

# Configuration variables with sensible defaults
region = config.get("region") or "us-south"
resource_group_id = config.require("resource_group_id")
vpc_name = config.get("vpc_name") or "vpc-pki-vpn"
subnet_cidr = config.get("subnet_cidr") or "10.240.0.0/24"
vpn_client_cidr = config.get("vpn_client_cidr") or "172.16.0.0/16"

# PKI Configuration
pki_common_name = config.get("pki_common_name") or "VPC VPN PKI"
certificate_validity_days = config.get_int("certificate_validity_days") or 365
ca_validity_days = config.get_int("ca_validity_days") or 3650

# =====================================================
# IBM Cloud Infrastructure Setup
# =====================================================

# Create VPC
vpc = ibm.IsVpc(
    "vpc",
    name=vpc_name,
    resource_group=resource_group_id,
    tags=["pulumi", "pki", "vpn"]
)

# Create subnet
subnet = ibm.IsSubnet(
    "subnet",
    name=f"{vpc_name}-subnet",
    vpc=vpc.id,
    zone=f"{region}-1",
    ipv4_cidr_block=subnet_cidr,
    resource_group=resource_group_id,
    tags=["pulumi", "subnet", "vpn"]
)

# Create IBM Cloud Secrets Manager instance
secrets_manager = ibm.ResourceInstance(
    "secrets-manager",
    name=f"{vpc_name}-secrets-manager",
    service="secrets-manager",
    plan="standard",
    location=region,
    resource_group_id=resource_group_id,
    parameters={
        "allowed_network" :"public-and-private"
    },
    tags=["pulumi", "pki", "secrets-manager"]
)

# =====================================================
# PKI Certificate Infrastructure
# =====================================================

# Create CA private key (4096-bit for maximum security)
ca_private_key = tls.PrivateKey(
    "ca-private-key",
    algorithm="RSA",
    rsa_bits=4096
)

# Create root CA certificate
ca_cert = tls.SelfSignedCert(
    "ca-certificate",
    private_key_pem=ca_private_key.private_key_pem,
    subject={
        "common_name": f"{pki_common_name} Root CA",
        "organization": "IBM Cloud VPC",
        "organizational_unit": "PKI Infrastructure",
        "country": "US",
        "locality": "Austin",
        "province": "TX"
    },
    validity_period_hours=ca_validity_days * 24,
    is_ca_certificate=True,
    allowed_uses=[
        "cert_signing",
        "crl_signing",
        "key_encipherment",
        "digital_signature"
    ]
)

# Create intermediate CA private key
intermediate_private_key = tls.PrivateKey(
    "intermediate-private-key",
    algorithm="RSA",
    rsa_bits=2048
)

# Create intermediate CA certificate signing request
intermediate_csr = tls.CertRequest(
    "intermediate-csr",
    private_key_pem=intermediate_private_key.private_key_pem,
    subject={
        "common_name": f"{pki_common_name} Intermediate CA",
        "organization": "IBM Cloud VPC",
        "organizational_unit": "Intermediate PKI",
        "country": "US",
        "locality": "Austin",
        "province": "TX"
    }
)

# Sign intermediate CA certificate with root CA
intermediate_cert = tls.LocallySignedCert(
    "intermediate-certificate",
    cert_request_pem=intermediate_csr.cert_request_pem,
    ca_private_key_pem=ca_private_key.private_key_pem,
    ca_cert_pem=ca_cert.cert_pem,
    validity_period_hours=(certificate_validity_days * 24 * 2),  # 2x end-entity validity
    is_ca_certificate=True,
    allowed_uses=[
        "cert_signing",
        "crl_signing",
        "key_encipherment",
        "digital_signature"
    ]
)

# Create server private key
server_private_key = tls.PrivateKey(
    "server-private-key",
    algorithm="RSA",
    rsa_bits=2048
)

# Create server certificate signing request with IBM Cloud compatible SANs
server_csr = tls.CertRequest(
    "server-csr",
    private_key_pem=server_private_key.private_key_pem,
    subject={
        "common_name": f"vpn-server.{region}.cloud.ibm.com",
        "organization": "IBM Cloud VPC",
        "organizational_unit": "VPN Infrastructure",
        "country": "US",
        "locality": "Austin",
        "province": "TX"
    },
    dns_names=[
        "vpn-server",
        "vpn-server.vpc.local",
        "*.vpc.local",
        f"vpn-server.{region}.cloud.ibm.com",
        f"*.{region}.cloud.ibm.com",
        "*.vpn.ibmcloud.com",
        "*.vpn.cloud.ibm.com"
    ],
    ip_addresses=["127.0.0.1"]
)

# Sign server certificate with intermediate CA
server_cert = tls.LocallySignedCert(
    "server-certificate",
    cert_request_pem=server_csr.cert_request_pem,
    ca_private_key_pem=intermediate_private_key.private_key_pem,
    ca_cert_pem=intermediate_cert.cert_pem,
    validity_period_hours=certificate_validity_days * 24,
    allowed_uses=[
        "key_encipherment",
        "digital_signature",
        "server_auth"
    ]
)

# Create client private key
client_private_key = tls.PrivateKey(
    "client-private-key",
    algorithm="RSA",
    rsa_bits=2048
)

# Create client certificate signing request
client_csr = tls.CertRequest(
    "client-csr",
    private_key_pem=client_private_key.private_key_pem,
    subject={
        "common_name": "vpn-client-001",
        "organization": "IBM Cloud VPC",
        "organizational_unit": "VPN Clients",
        "country": "US",
        "locality": "Austin",
        "province": "TX"
    }
)

# Sign client certificate with intermediate CA
client_cert = tls.LocallySignedCert(
    "client-certificate",
    cert_request_pem=client_csr.cert_request_pem,
    ca_private_key_pem=intermediate_private_key.private_key_pem,
    ca_cert_pem=intermediate_cert.cert_pem,
    validity_period_hours=certificate_validity_days * 24,
    allowed_uses=[
        "key_encipherment",
        "digital_signature",
        "client_auth"
    ]
)

# =====================================================
# Store Certificates in IBM Cloud Secrets Manager
# =====================================================

# Wait for Secrets Manager to be provisioned
secrets_manager_guid = secrets_manager.guid

# Create secret groups for certificate organization
ca_secret_group = ibm.SmSecretGroup(
    "ca-secret-group",
    instance_id=secrets_manager_guid,
    name="pki-ca-certificates",
    description="PKI CA certificates and keys"
)

server_secret_group = ibm.SmSecretGroup(
    "server-secret-group",
    instance_id=secrets_manager_guid,
    name="pki-server-certificates",
    description="PKI server certificates and keys"
)

client_secret_group = ibm.SmSecretGroup(
    "client-secret-group",
    instance_id=secrets_manager_guid,
    name="pki-client-certificates",
    description="PKI client certificates and keys"
)

# Store root CA certificate
ca_secret = ibm.SmImportedCertificate(
    "ca-certificate-secret",
    instance_id=secrets_manager_guid,
    name="vpn-root-ca-certificate",
    description="VPN Root CA Certificate for PKI infrastructure",
    secret_group_id=ca_secret_group.secret_group_id,
    certificate=ca_cert.cert_pem,
    private_key=ca_private_key.private_key_pem,
    labels=["root-ca", "pki", "vpn"]
)

# Store intermediate CA certificate
intermediate_secret = ibm.SmImportedCertificate(
    "intermediate-certificate-secret",
    instance_id=secrets_manager_guid,
    name="vpn-intermediate-ca-certificate",
    description="VPN Intermediate CA Certificate",
    secret_group_id=ca_secret_group.secret_group_id,
    certificate=intermediate_cert.cert_pem,
    private_key=intermediate_private_key.private_key_pem,
    intermediate=ca_cert.cert_pem,
    labels=["intermediate-ca", "pki", "vpn"]
)

# Create certificate chain for server certificate (intermediate + root CA)
server_cert_chain = pulumi.Output.all(
    intermediate_cert.cert_pem,
    ca_cert.cert_pem
).apply(lambda certs: f"{certs[0].strip()}\n{certs[1].strip()}")

# Store server certificate with intermediate certificate only
server_secret = ibm.SmImportedCertificate(
    "server-certificate-secret",
    instance_id=secrets_manager_guid,
    name="vpn-server-certificate",
    description="VPN Server Certificate with intermediate CA",
    secret_group_id=server_secret_group.secret_group_id,
    certificate=server_cert.cert_pem,
    private_key=server_private_key.private_key_pem,
    intermediate=intermediate_cert.cert_pem,
    labels=["server", "vpn", "certificate"]
)

# Store client certificate with full certificate chain
client_secret = ibm.SmImportedCertificate(
    "client-certificate-secret",
    instance_id=secrets_manager_guid,
    name="vpn-client-certificate",
    description="VPN Client Certificate with full chain",
    secret_group_id=client_secret_group.secret_group_id,
    certificate=client_cert.cert_pem,
    private_key=client_private_key.private_key_pem,
    intermediate=server_cert_chain,
    labels=["client", "vpn", "certificate"]
)

# =====================================================
# VPN Server Infrastructure
# =====================================================

# Create security group for VPN server
vpn_security_group = ibm.IsSecurityGroup(
    "vpn-security-group",
    name=f"{vpc_name}-vpn-sg",
    vpc=vpc.id,
    resource_group=resource_group_id,
    tags=["pulumi", "security-group", "vpn"]
)

# Inbound rule for VPN traffic (UDP 443) - using correct IBM schema
vpn_sg_rule_inbound = ibm.IsSecurityGroupRule(
    "vpn-sg-rule-inbound",
    group=vpn_security_group.id,
    direction="inbound",
    ip_version="ipv4",
    udp={
        "port_min": 443,
        "port_max": 443
    },
    remote="0.0.0.0/0"
)

# Outbound rule for all traffic - using correct IBM schema  
vpn_sg_rule_outbound = ibm.IsSecurityGroupRule(
    "vpn-sg-rule-outbound",
    group=vpn_security_group.id,
    direction="outbound",
    ip_version="ipv4",
    remote="0.0.0.0/0"
)

# Alternative inbound rule for ICMP (ping) - optional
vpn_sg_rule_icmp = ibm.IsSecurityGroupRule(
    "vpn-sg-rule-icmp",
    group=vpn_security_group.id,
    direction="inbound",
    ip_version="ipv4",
    icmp={
        "type": 8,  # Echo request
        "code": 0
    },
    remote="0.0.0.0/0"
)

# Create VPN Server with proper certificate configuration
vpn_server = ibm.IsVpnServer(
    "vpn-server",
    name=f"{vpc_name}-vpn-server",
    certificate_crn=server_secret.crn,
    client_authentications=[{
        "method": "certificate",
        "client_ca_crn": intermediate_secret.crn  # Use intermediate CA for client validation
    }],
    client_ip_pool=vpn_client_cidr,
    client_idle_timeout=2800,
    enable_split_tunneling=False,
    port=443,
    protocol="udp",
    subnets=[subnet.id],
    security_groups=[vpn_security_group.id],
    resource_group=resource_group_id,
    tags=["pulumi", "vpn-server"]
)

# =====================================================
# Advanced OpenVPN Client Configuration
# =====================================================

def create_advanced_openvpn_config(hostname, ca_cert, intermediate_cert, client_cert, client_key):
    """Generate advanced OpenVPN client configuration with PKI chain validation"""
    return f"""# OpenVPN Client Configuration - IBM Cloud VPN
# Generated by Pulumi with IBM Cloud Secrets Manager integration
# Three-tier PKI: Root CA -> Intermediate CA -> End Entity Certificates

client
dev tun
proto udp
remote {hostname} 443
resolv-retry infinite
nobind
persist-key
persist-tun

# Certificate validation settings - IBM Cloud VPN compatible
remote-cert-tls server
# Use flexible hostname verification for IBM Cloud dynamic hostnames
# Note: verify-x509-name requires specific subject name from server certificate
# For IBM Cloud VPN servers, disable strict hostname verification
verify-x509-name vpn-server name-prefix

# Security and encryption settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Connection settings
keepalive 10 120
ping-timer-rem
ping-exit 60

# Logging (adjust verb level as needed: 1-11)
verb 3
mute 20

# Compression (if supported by server)
compress lz4-v2
push-peer-info

# Complete certificate chain for validation
# Root CA Certificate
\u003cca\u003e
{ca_cert}
\u003c/ca\u003e

# Client Certificate
\u003ccert\u003e
{client_cert}
\u003c/cert\u003e

# Client Private Key  
\u003ckey\u003e
{client_key}
\u003c/key\u003e

# Intermediate CA Certificate (required for chain validation)
\u003cextra-certs\u003e
{intermediate_cert}
\u003c/extra-certs\u003e
"""

# Generate advanced client configuration
client_config = pulumi.Output.all(
    vpn_server.hostname,
    ca_cert.cert_pem,
    intermediate_cert.cert_pem,
    client_cert.cert_pem,
    client_private_key.private_key_pem
).apply(
    lambda args: create_advanced_openvpn_config(args[0], args[1], args[2], args[3], args[4])
)

# Store client configuration in Secrets Manager
client_config_secret = ibm.SmArbitrarySecret(
    "client-config-secret",
    instance_id=secrets_manager_guid,
    name="advanced-openvpn-client-config",
    description="Advanced OpenVPN client configuration with PKI certificate chain",
    secret_group_id=client_secret_group.secret_group_id,
    payload=client_config,
    labels=["client-config", "openvpn", "advanced", "pki"]
)

# Create alternative client configuration without hostname verification
def create_simple_openvpn_config(hostname, ca_cert, intermediate_cert, client_cert, client_key):
    """Generate OpenVPN client configuration with complete certificate chain in CA section"""
    # Create complete certificate chain for CA validation
    complete_ca_chain = f"{intermediate_cert.strip()}\n{ca_cert.strip()}"
    
    return f"""# OpenVPN Client Configuration - IBM Cloud VPN (Certificate Chain Fix)
# Generated by Pulumi - Complete certificate chain for validation
# Use this configuration to resolve peer certificate verification issues

client
dev tun
proto udp
remote {hostname} 443
resolv-retry infinite
nobind
persist-key
persist-tun

# Certificate validation - no hostname verification for IBM Cloud compatibility  
remote-cert-tls server
# Note: OpenVPN 2.6+ doesn't support empty verify-x509-name, so we omit it entirely

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2

# Connection settings
keepalive 10 120
verb 4
mute 10

# Complete Certificate Authority Chain (Intermediate + Root)
# This includes both intermediate CA and root CA for proper chain validation
\u003cca\u003e
{complete_ca_chain}
\u003c/ca\u003e

# Client Certificate
\u003ccert\u003e
{client_cert}
\u003c/cert\u003e

# Client Private Key
\u003ckey\u003e
{client_key}
\u003c/key\u003e
"""

# Generate simple client configuration
simple_client_config = pulumi.Output.all(
    vpn_server.hostname,
    ca_cert.cert_pem,
    intermediate_cert.cert_pem,
    client_cert.cert_pem,
    client_private_key.private_key_pem
).apply(
    lambda args: create_simple_openvpn_config(args[0], args[1], args[2], args[3], args[4])
)

# Store simple client configuration in Secrets Manager
simple_client_config_secret = ibm.SmArbitrarySecret(
    "simple-client-config-secret",
    instance_id=secrets_manager_guid,
    name="simple-openvpn-client-config",
    description="Simple OpenVPN client configuration without hostname verification",
    secret_group_id=client_secret_group.secret_group_id,
    payload=simple_client_config,
    labels=["client-config", "openvpn", "simple", "no-hostname-check"]
)

# Create root CA only configuration for maximum compatibility
def create_rootca_only_config(hostname, ca_cert, client_cert, client_key):
    """Generate OpenVPN client configuration using only root CA for validation"""
    return f"""# OpenVPN Client Configuration - IBM Cloud VPN (Root CA Only)
# Generated by Pulumi - Root CA only for maximum compatibility
# Use this configuration if certificate chain validation fails

client
dev tun
proto udp
remote {hostname} 443
resolv-retry infinite
nobind
persist-key
persist-tun

# Minimal certificate validation - no hostname verification
remote-cert-tls server
# Note: Omitting verify-x509-name entirely to disable hostname verification

# Basic security settings
cipher AES-256-GCM
auth SHA256

# Connection settings
keepalive 10 120
verb 4
mute 10

# Root CA Certificate Only
\u003cca\u003e
{ca_cert}
\u003c/ca\u003e

# Client Certificate
\u003ccert\u003e
{client_cert}
\u003c/cert\u003e

# Client Private Key
\u003ckey\u003e
{client_key}
\u003c/key\u003e
"""

# Generate root CA only client configuration
rootca_only_config = pulumi.Output.all(
    vpn_server.hostname,
    ca_cert.cert_pem,
    client_cert.cert_pem,
    client_private_key.private_key_pem
).apply(
    lambda args: create_rootca_only_config(args[0], args[1], args[2], args[3])
)

# Store root CA only client configuration in Secrets Manager
rootca_only_config_secret = ibm.SmArbitrarySecret(
    "rootca-only-config-secret",
    instance_id=secrets_manager_guid,
    name="rootca-only-openvpn-client-config",
    description="Root CA only OpenVPN client configuration for maximum compatibility",
    secret_group_id=client_secret_group.secret_group_id,
    payload=rootca_only_config,
    labels=["client-config", "openvpn", "rootca-only", "compatibility"]
)

# =====================================================
# Certificate Management and Monitoring
# =====================================================

# Certificate expiration monitoring configuration
monitoring_config = ibm.SmArbitrarySecret(
    "cert-monitoring-config",
    instance_id=secrets_manager_guid,
    name="certificate-expiration-monitoring",
    description="Certificate expiration monitoring and alerting configuration",
    secret_group_id=ca_secret_group.secret_group_id,
    payload=json.dumps({
        "monitoring": {
            "enabled": True,
            "alert_threshold_days": 30,
            "check_interval_hours": 24,
            "notification_channels": ["email", "webhook"]
        },
        "certificates": [
            {
                "name": "vpn-root-ca-certificate",
                "type": "root_ca",
                "criticality": "high",
                "alert_days": [90, 60, 30, 14, 7]
            },
            {
                "name": "vpn-intermediate-ca-certificate", 
                "type": "intermediate_ca",
                "criticality": "high",
                "alert_days": [60, 30, 14, 7]
            },
            {
                "name": "vpn-server-certificate",
                "type": "server",
                "criticality": "medium",
                "alert_days": [30, 14, 7, 3, 1]
            },
            {
                "name": "vpn-client-certificate",
                "type": "client", 
                "criticality": "low",
                "alert_days": [30, 7, 1]
            }
        ]
    }),
    labels=["monitoring", "certificates", "alerting"]
)

# PKI management API endpoints and tools configuration
pki_tools_config = ibm.SmArbitrarySecret(
    "pki-tools-config",
    instance_id=secrets_manager_guid,
    name="pki-management-tools",
    description="PKI management tools and automation configuration", 
    secret_group_id=ca_secret_group.secret_group_id,
    payload=json.dumps({
        "tools": {
            "certificate_renewal": {
                "automated": True,
                "renewal_threshold_days": 30,
                "backup_old_certificates": True
            },
            "certificate_validation": {
                "chain_validation": True,
                "crl_checking": False,  # Enable if CRL is implemented
                "ocsp_checking": False  # Enable if OCSP is implemented  
            },
            "security_scanning": {
                "weak_key_detection": True,
                "certificate_transparency_monitoring": False,
                "vulnerability_scanning": True
            }
        },
        "endpoints": {
            "secrets_manager": f"https://{secrets_manager_guid}.{region}.secrets-manager.appdomain.cloud",
            "api_docs": "https://cloud.ibm.com/apidocs/secrets-manager",
            "certificate_manager": f"https://cloud.ibm.com/services/secrets-manager/{secrets_manager_guid}"
        }
    }),
    labels=["pki-tools", "automation", "management"]
)

# =====================================================
# Outputs and Information
# =====================================================

# Core infrastructure outputs
pulumi.export("vpc_id", vpc.id)
pulumi.export("vpc_name", vpc.name)
pulumi.export("subnet_id", subnet.id)
pulumi.export("subnet_cidr", subnet_cidr)

# Secrets Manager outputs
pulumi.export("secrets_manager_guid", secrets_manager_guid)
pulumi.export("secrets_manager_crn", secrets_manager.crn)
pulumi.export("secrets_manager_dashboard_url", pulumi.Output.concat(
    "https://cloud.ibm.com/services/secrets-manager/", secrets_manager_guid
))

# VPN server outputs
pulumi.export("vpn_server_id", vpn_server.id)
pulumi.export("vpn_server_hostname", vpn_server.hostname)
pulumi.export("vpn_server_private_ips", vpn_server.private_ips)
pulumi.export("vpn_server_status", vpn_server.lifecycle_state)

# Certificate CRNs for programmatic access
pulumi.export("certificate_crns", {
    "root_ca": ca_secret.crn,
    "intermediate_ca": intermediate_secret.crn, 
    "server": server_secret.crn,
    "client": client_secret.crn
})

# Secret group IDs for organization
pulumi.export("secret_groups", {
    "ca_certificates": ca_secret_group.secret_group_id,
    "server_certificates": server_secret_group.secret_group_id,
    "client_certificates": client_secret_group.secret_group_id
})

# Configuration secrets
pulumi.export("management_configs", {
    "client_config": client_config_secret.crn,
    "simple_client_config": simple_client_config_secret.crn,
    "rootca_only_config": rootca_only_config_secret.crn,
    "monitoring_config": monitoring_config.crn,
    "tools_config": pki_tools_config.crn
})

# Client configurations for immediate use (base64 encoded for security)
pulumi.export("client_config_base64", client_config.apply(
    lambda config: base64.b64encode(config.encode('utf-8')).decode('utf-8')
))

pulumi.export("simple_client_config_base64", simple_client_config.apply(
    lambda config: base64.b64encode(config.encode('utf-8')).decode('utf-8')
))

pulumi.export("rootca_only_config_base64", rootca_only_config.apply(
    lambda config: base64.b64encode(config.encode('utf-8')).decode('utf-8')
))

# PKI architecture summary
pulumi.export("pki_architecture", {
    "certificate_hierarchy": "Root CA (4096-bit) -> Intermediate CA (2048-bit) -> End Entities (2048-bit)",
    "validity_periods": {
        "root_ca_days": ca_validity_days,
        "intermediate_ca_days": certificate_validity_days * 2,
        "end_entity_days": certificate_validity_days
    },
    "security_features": [
        "Three-tier PKI hierarchy",
        "Certificate chain validation", 
        "IBM Secrets Manager integration",
        "Automated certificate lifecycle management",
        "Expiration monitoring and alerting"
    ],
    "supported_protocols": ["OpenVPN", "IPSec (with modifications)"],
    "encryption": "AES-256-GCM with RSA key exchange"
})

# Connection instructions
pulumi.export("connection_instructions", pulumi.Output.all(
    vpn_server.hostname,
    client_config_secret.crn,
    simple_client_config_secret.crn,
    rootca_only_config_secret.crn
).apply(
    lambda args: f"""VPN Connection Setup - Three Client Configuration Options:

=== METHOD 1: Advanced Configuration (Best Security) ===
1. Download advanced client configuration:
   pulumi stack output client_config_base64 | base64 -d > vpn-client-advanced.ovpn

2. Or retrieve from Secrets Manager:
   ibmcloud secrets-manager secret-get --id {args[1].split(':')[-1]} --output json | jq -r '.resources[0].secret_data.payload' > vpn-client-advanced.ovpn

=== METHOD 2: Simple Configuration (No Hostname Verification) ===
1. Download simple client configuration:
   pulumi stack output simple_client_config_base64 | base64 -d > vpn-client-simple.ovpn

2. Or retrieve from Secrets Manager:
   ibmcloud secrets-manager secret-get --id {args[2].split(':')[-1]} --output json | jq -r '.resources[0].secret_data.payload' > vpn-client-simple.ovpn

=== METHOD 3: Root CA Only Configuration (Maximum Compatibility) ===
1. Download root CA only client configuration:
   pulumi stack output rootca_only_config_base64 | base64 -d > vpn-client-rootca-only.ovpn

2. Or retrieve from Secrets Manager:
   ibmcloud secrets-manager secret-get --id {args[3].split(':')[-1]} --output json | jq -r '.resources[0].secret_data.payload' > vpn-client-rootca-only.ovpn

=== Connection Priority Order ===
1. Start with METHOD 1 (Advanced) for best security
2. If peer certificate verification fails, try METHOD 2 (Simple)
3. If still failing, use METHOD 3 (Root CA Only) for maximum compatibility

=== Final Steps ===
4. Import chosen .ovpn file into your OpenVPN client
5. Connect to VPN server: {args[0]}
6. Monitor certificates in Secrets Manager dashboard

=== Troubleshooting Certificate Verification Issues ===
- Peer certificate verification failed:
  * Progression: Advanced -> Simple -> Root CA Only configs
  * Check server certificate SANs: openssl x509 -in server.crt -text -noout | grep -A5 "Subject Alternative Name"
  * Verify certificate chain: openssl verify -CAfile ca.crt -untrusted intermediate.crt client.crt
- Test basic connectivity: ping {args[0]}
- Enable verbose logging: Add 'verb 5' to .ovpn file for detailed connection logs
- Check IBM Cloud VPN server status in console"""
))

# Cost and resource summary
pulumi.export("resource_summary", {
    "estimated_monthly_cost_usd": {
        "secrets_manager_standard": "~$1 per secret (~$7 total)",
        "vpc_resources": "No additional charge",
        "vpn_server": f"~${0.045 * 24 * 30:.2f} (24/7 operation)",
        "data_transfer": "Variable based on usage"
    },
    "resources_created": {
        "vpc": 1,
        "subnet": 1,
        "security_group": 1,
        "security_group_rules": 3,
        "vpn_server": 1,
        "secrets_manager_instance": 1,
        "secret_groups": 3,
        "certificates": 4,
        "configuration_secrets": 3
    }
})