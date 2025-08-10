## IBM VPN Certificates

Pulumi program that provisions a client-to-site VPN on IBM Cloud VPC with a production-grade PKI and secure secret storage in IBM Cloud Secrets Manager. It automates:

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
Authentication to IBM Cloud for the Pulumi provider:
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
- Secrets Manager instance configuration (plan: `standard`, allowed network: `public-and-private`) is defined in code.
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
> :construction: More Pulumi code examples and articles coming soon.... 

> :star: this repository and keep a watch

# IBM VPN Certificates

A Pulumi program for generating and managing PKI certificates for VPN client-to-site authentication using IBM Cloud Secrets Manager.

## Overview

This project automates the creation of a complete certificate authority (CA) and certificate infrastructure for VPN deployments on IBM Cloud. It generates:

- Certificate Authority (CA) certificate and private key
- VPN server certificate and private key
- VPN client certificate and private key

All certificates are securely stored in IBM Cloud Secrets Manager for easy retrieval and management.

## Features

- **Automated PKI Management**: Generates a complete certificate hierarchy with CA, server, and client certificates
- **Secure Storage**: All certificates and keys are stored in IBM Cloud Secrets Manager
- **Configurable Parameters**: Extensive configuration options for certificate subjects, validity periods, and key sizes
- **Production Ready**: Uses industry-standard cryptographic practices and certificate extensions
- **IBM Cloud Integration**: Seamlessly integrates with IBM Cloud infrastructure and VPC services

## Prerequisites

- [Pulumi CLI](https://www.pulumi.com/docs/get-started/install/) installed
- [Python 3.7+](https://www.python.org/downloads/) installed
- IBM Cloud account with appropriate permissions
- IBM Cloud API key

## Quick Start

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd ibm-vpn-certificates
```

### 2. Install Dependencies

```bash
pulumi package add terraform-provider ibm-cloud/ibm
pip install -r requirements.txt
```

### 3. Configure IBM Cloud Authentication

Set your IBM Cloud API key:

```bash
# Option 1: Environment variable
export IBMCLOUD_API_KEY="your-api-key-here"

# Option 2: Pulumi secret
pulumi config set --secret ibmcloud:ibmcloudApiKey "<IBMCLOUD_API_KEY>"
```

### 4. Configure the Stack

```bash
# Initialize a new stack
pulumi stack init dev

# Set required configuration
pulumi config set resource_group_name "your-resource-group-name"
pulumi config set resource_group_id "your-resource-group-id"
pulumi config set region "us-south"
pulumi config set org_name "YourOrganization"
```

### 5. Deploy

```bash
pulumi preview
pulumi up
```

## Configuration

The project supports extensive configuration through Pulumi configuration values:

### IBM Cloud Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `resource_group_id` | IBM Cloud Resource Group GUID | - | No |
| `resource_group_name` | IBM Cloud Resource Group Name | `Default` | No |
| `region` | IBM Cloud Region | `us-south` | No |

¹ Either `resource_group_id` or `resource_group_name` must be provided

### Secrets Manager Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets_manager_name` | Name for Secrets Manager instance | `vpn-secrets-manager` |
| `secrets_manager_plan` | Service plan (standard/trial) | `standard` |
| `secrets_manager_service_endpoints` | Service endpoint access | `public-and-private` |
| `secret_group_name` | Name for certificate secret group | `vpn-certificates` |
| `secret_group_description` | Description for secret group | `Certificate group for VPN client-to-site authentication` |

### Certificate Subject Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `org_name` | Organization Name | `MyOrganization` |
| `country_code` | Country code (ISO 3166-1 alpha-2) | `US` |
| `state_province` | State or Province name | `Texas` |
| `locality` | Locality (city) name | `Austin` |
| `ca_common_name` | CA certificate Common Name | `VPN CA` |
| `server_common_name` | Server certificate Common Name | `VPN Server` |
| `client_common_name` | Client certificate Common Name | `VPN Client` |

### Certificate Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ca_validity_days` | CA certificate validity period | `3650` (10 years) |
| `cert_validity_days` | Server/client certificate validity | `365` (1 year) |
| `key_size` | RSA key size in bits | `2048` |

### Secret Names Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ca_cert_secret_name` | CA certificate secret name | `vpn-ca-certificate` |
| `ca_key_secret_name` | CA private key secret name | `vpn-ca-private-key` |
| `server_cert_secret_name` | Server certificate secret name | `vpn-server-certificate` |
| `server_key_secret_name` | Server private key secret name | `vpn-server-private-key` |
| `client_cert_secret_name` | Client certificate secret name | `vpn-client-certificate` |
| `client_key_secret_name` | Client private key secret name | `vpn-client-private-key` |

### Optional Features

| Parameter | Description | Default |
|-----------|-------------|---------|
| `export_certificates` | Export certificate PEM data as outputs (⚠️ **Warning**: visible in plain text) | `false` |
| `enable_debug_output` | Enable debug output during deployment | `false` |

## Usage Examples

### Basic Deployment

```bash
pulumi config set resource_group_name "my-resource-group"
pulumi config set org_name "ACME Corporation"
pulumi up
```

### Custom Certificate Configuration

```bash
# Configure organization details
pulumi config set org_name "ACME Corporation"
pulumi config set country_code "CA"
pulumi config set state_province "Ontario"
pulumi config set locality "Toronto"

# Configure certificate validity
pulumi config set ca_validity_days 7300  # 20 years
pulumi config set cert_validity_days 730  # 2 years

# Configure key size
pulumi config set key_size 4096

# Deploy
pulumi up
```

### Multi-Environment Setup

```bash
# Production environment
pulumi stack init production
pulumi config set resource_group_name "prod-resources"
pulumi config set secrets_manager_name "prod-vpn-secrets"
pulumi config set org_name "ACME Corporation"

# Development environment  
pulumi stack init development
pulumi config set resource_group_name "dev-resources"
pulumi config set secrets_manager_name "dev-vpn-secrets"
pulumi config set secrets_manager_plan "trial"
pulumi config set org_name "ACME Corporation - Dev"
```

## Outputs

After deployment, the stack exports the following values:

### Secrets Manager Information
- `secrets_manager_guid`: GUID of the Secrets Manager instance
- `secrets_manager_crn`: Cloud Resource Name of Secrets Manager
- `secret_group_id`: ID of the certificate secret group

### Certificate Secret IDs
- `ca_certificate_id`: Secret ID for CA certificate
- `ca_private_key_id`: Secret ID for CA private key
- `server_certificate_id`: Secret ID for server certificate
- `server_private_key_id`: Secret ID for server private key
- `client_certificate_id`: Secret ID for client certificate
- `client_private_key_id`: Secret ID for client private key

### Certificate Information
- `certificate_info`: Metadata about generated certificates
- `secret_names`: Map of secret names for easy reference
- `certificate_crns`: CRNs of certificate secrets for VPN configuration

## Certificate Details

The generated certificates follow industry best practices:

### CA Certificate
- **Type**: Self-signed root CA
- **Key Usage**: Certificate Sign, CRL Sign, Digital Signature
- **Basic Constraints**: CA=true
- **Extensions**: Subject Key Identifier, Authority Key Identifier

### Server Certificate
- **Type**: Server authentication certificate
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Server Authentication
- **Basic Constraints**: CA=false

### Client Certificate
- **Type**: Client authentication certificate
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Client Authentication
- **Basic Constraints**: CA=false

## Retrieving Certificates

After deployment, certificates can be retrieved from IBM Cloud Secrets Manager:

### Using IBM Cloud CLI

```bash
# Get the Secrets Manager instance ID from Pulumi outputs
INSTANCE_ID=$(pulumi stack output secrets_manager_guid)

# Retrieve CA certificate
ibmcloud secrets-manager secret --instance-id $INSTANCE_ID --secret-id $(pulumi stack output ca_certificate_id)

# Retrieve server certificate
ibmcloud secrets-manager secret --instance-id $INSTANCE_ID --secret-id $(pulumi stack output server_certificate_id)
```

### Using IBM Cloud Console

1. Navigate to IBM Cloud Secrets Manager
2. Select your Secrets Manager instance
3. Browse to the "vpn-certificates" secret group
4. Download or view the required certificates

## Security Considerations

- **Private Key Security**: Private keys are stored encrypted in IBM Cloud Secrets Manager
- **Access Control**: Use IBM Cloud IAM to control access to Secrets Manager
- **Certificate Rotation**: Plan for regular certificate rotation before expiry
- **Export Warning**: Never enable `export_certificates` in production environments
- **API Key Security**: Store IBM Cloud API keys securely and rotate regularly

## Troubleshooting

### Common Issues

1. **Resource Group Not Found**
   ```
   Error: Could not find resource group 'Default'
   ```
   - Ensure the resource group exists in your IBM Cloud account
   - Check the resource group name spelling
   - Use `resource_group_id` instead if you have the GUID

2. **Authentication Failures**
   ```
   Error: Authentication failed
   ```
   - Verify your IBM Cloud API key is correct
   - Check API key permissions for Secrets Manager
   - Ensure the API key hasn't expired

3. **Quota Exceeded**
   ```
   Error: Service limit exceeded
   ```
   - Check your IBM Cloud service quotas
   - Consider using different regions
   - Contact IBM Cloud support for quota increases

### Debug Mode

Enable debug output for troubleshooting:

```bash
pulumi config set enable_debug_output true
pulumi up
```

## Project Structure

```
├── README.md                 # This file
├── Pulumi.yaml              # Main project configuration
├── __main__.py              # Main Pulumi program
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore rules
├── basics/                 # Basic Pulumi example
│   ├── Pulumi.yaml
│   ├── __main__.py
│   └── requirements.txt
└── sdks/                   # IBM Cloud SDK
    └── ibm/
        └── pulumi_ibm/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is distributed under the same license as the underlying IBM Cloud Terraform provider (MPL 2.0).

## Support

For issues related to:
- **Pulumi**: Check the [Pulumi documentation](https://www.pulumi.com/docs/)
- **IBM Cloud Provider**: Consult the [terraform-provider-ibm repository](https://github.com/ibm-cloud/terraform-provider-ibm/issues)
- **IBM Cloud Services**: Contact IBM Cloud Support

## Related Documentation

- [IBM Cloud Secrets Manager](https://cloud.ibm.com/docs/secrets-manager)
- [IBM Cloud VPC VPN](https://cloud.ibm.com/docs/vpc?topic=vpc-vpn-overview)
- [Pulumi IBM Cloud Provider](https://www.pulumi.com/registry/packages/ibm/)
- [Certificate Management Best Practices](https://cloud.ibm.com/docs/certificate-manager?topic=certificate-manager-about-certificate-manager)

## VPN Connection Setup

This project exports three OpenVPN client configuration options. Choose the most secure option that works in your environment.

=== METHOD 1: Advanced Configuration (Best Security) ===
1. Download advanced client configuration from Pulumi outputs:
   pulumi stack output --show-secrets client_config_base64 | base64 -d > vpn-client-advanced.ovpn

2. Or retrieve directly from Secrets Manager (requires IBM Cloud CLI and jq):
   ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.client_config' | awk -F: '{print $NF}') --output json \
     | jq -r '.resources[0].secret_data.payload' > vpn-client-advanced.ovpn

=== METHOD 2: Simple Configuration (No Hostname Verification) ===
1. Download simple client configuration from Pulumi outputs:
   pulumi stack output --show-secrets simple_client_config_base64 | base64 -d > vpn-client-simple.ovpn

2. Or retrieve from Secrets Manager:
   ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.simple_client_config' | awk -F: '{print $NF}') --output json \
     | jq -r '.resources[0].secret_data.payload' > vpn-client-simple.ovpn

=== METHOD 3: Root CA Only Configuration (Maximum Compatibility) ===
1. Download root CA only client configuration from Pulumi outputs:
   pulumi stack output --show-secrets rootca_only_config_base64 | base64 -d > vpn-client-rootca-only.ovpn

2. Or retrieve from Secrets Manager:
   ibmcloud secrets-manager secret-get --id $(pulumi stack output management_configs | jq -r '.rootca_only_config' | awk -F: '{print $NF}') --output json \
     | jq -r '.resources[0].secret_data.payload' > vpn-client-rootca-only.ovpn

=== Connection Priority Order ===
1. Start with METHOD 1 (Advanced) for best security
2. If peer certificate verification fails, try METHOD 2 (Simple)
3. If still failing, use METHOD 3 (Root CA Only) for maximum compatibility

=== Final Steps ===
4. Import the chosen .ovpn file into your OpenVPN client
5. Connect to the VPN server hostname exposed by the stack output `vpn_server_hostname`
6. Monitor certificates in the Secrets Manager dashboard (see `secrets_manager_dashboard_url` output)

=== Troubleshooting Certificate Verification Issues ===
- Peer certificate verification failed:
  * Progression: Advanced -> Simple -> Root CA Only configs
  * Check server certificate SANs:
    openssl x509 -in server.crt -text -noout | grep -A5 "Subject Alternative Name"
  * Verify certificate chain:
    openssl verify -CAfile ca.crt -untrusted intermediate.crt client.crt
- Test basic connectivity to the VPN hostname using ping
- Enable verbose logging: add `verb 5` to the .ovpn file for detailed logs
- Check IBM Cloud VPN server status in the IBM Cloud console

## Resource Summary

Resources created:
- VPC: 1
- Subnet: 1
- Security group: 1
- Security group rules: 3
- VPN server: 1
- Secrets Manager instance: 1
- Secret groups: 3
- Certificates: 4
- Configuration secrets: 3
