> :construction: More Pulumi code examples and articles coming soon.... 

> :star:  this repository and keep a watch 

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
