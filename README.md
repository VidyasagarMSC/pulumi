## IBM VPN Certificates

Pulumi program that provisions a client-to-site VPN on IBM Cloud VPC with a production-grade PKI and secure secret storage in IBM Cloud Secrets Manager.

It automates:
- Root and Intermediate CAs (keys and certificates)
- VPN server and client certificates
- IBM Cloud Secrets Manager instance and secret groups
- IBM Cloud VPC, Subnet, Security Group and rules
- IBM Cloud VPC VPN Server (UDP/443)
- Three OpenVPN client configuration files (advanced, simple, root-CA-only)

All artifacts (certs, keys, configs) are stored as Secrets Manager secrets. The stack exports friendly outputs and base64-encoded client configs for quick download.

### Project Overview
- Purpose: Provide a secure, reproducible reference for standing up a VPC VPN service with a three-tier PKI on IBM Cloud using Pulumi.
- Scope: VPC networking, Secrets Manager, PKI generation, VPN server, client configs, and basic monitoring metadata.

### Prerequisites
- Pulumi CLI
- Python 3.9+
- IBM Cloud account and API key with permissions to create VPC and Secrets Manager resources
- Optional but recommended:
  - IBM Cloud CLI (`ibmcloud`) and `jq` for retrieving secrets via CLI
  - An OpenVPN client to test connectivity

### Installation
1) Clone and set up a virtual environment
```bash
git clone <your-repo-url>
cd ibm-vpn-certificates
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

2) Pre-install provider plugins (Pulumi can also auto-install on first run)
```bash
pulumi plugin install resource ibm 1.81.1
pulumi plugin install resource tls 4.0.0
```

### Configuration
Authenticate for the Pulumi IBM provider:
```bash
export IBMCLOUD_API_KEY="<your-api-key>"
# or store as a Pulumi secret (preferred for CI/shared envs)
pulumi config set --secret ibmcloud:ibmcloudApiKey "<your-api-key>"
```

Create a stack and set required/effective configuration values (consumed in `stack/config.py`):
```bash
pulumi stack init dev
pulumi config set ibm-vpn-certificates:resource_group_id "<resource-group-guid>"

# Optional overrides
pulumi config set ibm-vpn-certificates:region us-south
pulumi config set ibm-vpn-certificates:vpc_name vpc-pki-vpn
pulumi config set ibm-vpn-certificates:subnet_cidr 10.240.0.0/24
pulumi config set ibm-vpn-certificates:vpn_client_cidr 172.16.0.0/16
pulumi config set ibm-vpn-certificates:pki_common_name "VPC VPN PKI"
pulumi config set ibm-vpn-certificates:certificate_validity_days 365
pulumi config set ibm-vpn-certificates:ca_validity_days 3650
```

Effective configuration keys:

| Key | Description | Default |
| --- | --- | --- |
| `resource_group_id` | IBM Cloud Resource Group GUID | required |
| `region` | IBM Cloud Region | `us-south` |
| `vpc_name` | Base name for VPC resources | `vpc-pki-vpn` |
| `subnet_cidr` | Subnet CIDR (zone `${region}-1`) | `10.240.0.0/24` |
| `vpn_client_cidr` | VPN client IP pool | `172.16.0.0/16` |
| `pki_common_name` | Base CN for certificates | `VPC VPN PKI` |
| `certificate_validity_days` | End-entity cert validity | `365` |
| `ca_validity_days` | Root CA validity | `3650` |

Notes:
- Secrets Manager instance configuration (plan: `standard`, allowed network: `public-and-private`) is defined in code (`stack/secrets.py`).
- Provider source is declared in `Pulumi.yaml`; Pulumi installs it automatically when needed.

### Project Structure
```
├── Pulumi.yaml              # Project definition and provider reference
├── Pulumi.<stack>.yaml      # Per-stack config (created by you)
├── __main__.py              # Orchestration: wires modules and exports outputs
├── requirements.txt         # Python dependencies (pulumi, pulumi-ibm, pulumi-tls, cryptography)
├── stack/
│   ├── config.py            # Reads Pulumi config into a typed dataclass
│   ├── infra.py             # VPC, Subnet, and basic networking
│   ├── secrets.py           # Secrets Manager instance and secret groups
│   ├── pki.py               # Creates keys/certs, imports them into Secrets Manager
│   ├── vpn.py               # IBM Cloud VPC VPN server + security group rules
│   ├── client_configs.py    # Generates OpenVPN configs and stores as secrets
│   ├── monitoring.py        # Monitoring/tooling config stored as secrets
│   └── outputs.py           # All Pulumi stack exports
├── basics/                  # Minimal Pulumi Python example (hello world)
└── sdks/ibm                 # Local provider artifacts (not edited by users)
```

### Usage / Running the Code
Plan and deploy:
```bash
pulumi preview
pulumi up
```

Inspect outputs:
```bash
pulumi stack output
```

Tear down all resources:
```bash
pulumi destroy
```

What gets created:
- VPC and Subnet in zone `${region}-1`
- Security Group + rules (UDP/443 inbound, ICMP inbound, all outbound)
- Secrets Manager instance and three secret groups
- Root CA, Intermediate CA, Server, and Client certificate secrets
- IBM Cloud VPC VPN Server (UDP/443) using the server certificate; client auth chained to Intermediate CA
- Three OpenVPN client configuration secrets and their base64 outputs

### Examples / Usage Scenarios
- Basic deployment with defaults
  ```bash
  pulumi config set ibm-vpn-certificates:resource_group_id "<guid>"
  pulumi up
  ```

- Customize validity and names
  ```bash
  pulumi config set ibm-vpn-certificates:pki_common_name "Corp VPN PKI"
  pulumi config set ibm-vpn-certificates:certificate_validity_days 730
  pulumi config set ibm-vpn-certificates:ca_validity_days 7300
  pulumi up
  ```

- Retrieve OpenVPN client configuration (three options)
  - Advanced (best security)
    ```bash
    pulumi stack output --show-secrets client_config_base64 | base64 -d > vpn-client-advanced.ovpn
    # Or via Secrets Manager (requires ibmcloud CLI and jq)
    ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.client_config' | awk -F: '{print $NF}') --output json \
      | jq -r '.resources[0].secret_data.payload' > vpn-client-advanced.ovpn
    ```
  - Simple (no hostname verification)
    ```bash
    pulumi stack output --show-secrets simple_client_config_base64 | base64 -d > vpn-client-simple.ovpn
    ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.simple_client_config' | awk -F: '{print $NF}') --output json \
      | jq -r '.resources[0].secret_data.payload' > vpn-client-simple.ovpn
    ```
  - Root CA only (maximum compatibility)
    ```bash
    pulumi stack output --show-secrets rootca_only_config_base64 | base64 -d > vpn-client-rootca-only.ovpn
    ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.rootca_only_config' | awk -F: '{print $NF}') --output json \
      | jq -r '.resources[0].secret_data.payload' > vpn-client-rootca-only.ovpn
    ```

Connect using the exported `vpn_server_hostname`.

### Testing
There is no formal test suite. Recommended validation steps:
- Run a dry run: `pulumi preview`
- Verify outputs after deployment: `pulumi stack output`
- Validate certificate chain locally (optional):
  ```bash
  openssl verify -CAfile ca.crt -untrusted intermediate.crt client.crt
  ```
- Test connectivity using the generated `.ovpn` file in your OpenVPN client.

### Troubleshooting
- Resource Group not found
  - Ensure the `resource_group_id` is correct and belongs to your account.
- Provider plugin or dependency issues
  - Re-install plugins: `pulumi plugin install resource ibm 1.81.1 && pulumi plugin install resource tls 4.0.0`
  - Recreate venv and reinstall `pip install -r requirements.txt`
- VPN connection issues / certificate verification
  - Try config priority: Advanced → Simple → Root CA only
  - Inspect server certificate SANs:
    ```bash
    openssl x509 -in server.crt -text -noout | grep -A5 "Subject Alternative Name"
    ```
  - Increase OpenVPN client verbosity: add `verb 5` to the `.ovpn` file for logs

### Frequently Asked Questions (FAQ)
- Does this expose private keys as outputs?
  - No. Keys and certs are stored in Secrets Manager. Client configs are exported base64-encoded but should be treated as sensitive.
- Can I change Secrets Manager plan/endpoints?
  - Not via config today; values are defined in `stack/secrets.py`. You can adjust and re-deploy.

### Roadmap / Future Plans
- Multiple client certificate generations and revocation workflows
- Automated rotation and renewal jobs
- Additional VPN profiles and protocols

### Contributing
Contributions are welcome:
1. Fork the repo and create a feature branch
2. Make changes with clear commits and adhere to Python formatting
3. Test with `pulumi preview` and `pulumi up` in a sandbox account
4. Open a Pull Request with context and screenshots/logs if relevant

### License
Distributed under MPL-2.0 (aligned with the IBM Cloud Terraform provider). If your organization requires a different license, propose it in a PR.

### Acknowledgments / Credits
- Pulumi and the Pulumi IBM Cloud provider
- IBM Cloud VPC and Secrets Manager services
