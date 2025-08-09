#!/usr/bin/env python3

from stack.config import load_config
from stack.infra import create_network
from stack.secrets import create_secrets_manager, create_secret_groups
from stack.pki import create_pki, store_certificates
from stack.vpn import create_vpn_server
from stack.client_configs import create_client_configs
from stack.monitoring import create_monitoring_tools
from stack.outputs import export_outputs

cfg = load_config()

# Infra
vpc, subnet = create_network(cfg)

# Secrets Manager and groups
secrets_manager, secrets_manager_guid = create_secrets_manager(cfg)
ca_group, server_group, client_group = create_secret_groups(secrets_manager_guid)

# PKI (keys and certs)
pki = create_pki(cfg)

# Store certs in Secrets Manager
cert_secrets = store_certificates(secrets_manager_guid, ca_group, server_group, client_group, pki)

# VPN server
vpn_server = create_vpn_server(cfg, vpc, subnet, cert_secrets)

# Client configs (stored as secrets)
client_configs = create_client_configs(secrets_manager_guid, client_group, vpn_server, pki, cert_secrets)

# Monitoring and tools configs
monitoring, tools = create_monitoring_tools(secrets_manager_guid, ca_group, cfg)

# Exports
export_outputs(cfg, vpc, subnet, secrets_manager, secrets_manager_guid, vpn_server, cert_secrets, client_configs, monitoring, tools)
