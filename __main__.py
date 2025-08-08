import pulumi
import pulumi_ibm as ibm
from cryptography import x509

# Configure IBM Cloud Provider
config = pulumi.Config()
ibm_api_key = config.get_secret("ibmcloud_api_key") or config.get_secret("bluemix_api_key")

# Create provider instance with API key if provided
if ibm_api_key:
    ibm_provider = ibm.Provider("ibm-provider", 
                               ibmcloud_api_key=ibm_api_key,
                               region=config.get("region") or "us-south")
else:
    ibm_provider = None
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import base64

# Configuration
config = pulumi.Config()

# IBM Cloud Configuration
resource_group_id = config.get("resource_group_id")
resource_group_name = config.get("resource_group_name") or "Default"
region = config.get("region") or "us-south"

# Secrets Manager Configuration
secrets_manager_name = config.get("secrets_manager_name") or "vpn-secrets-manager"
secrets_manager_plan = config.get("secrets_manager_plan") or "standard"
secrets_manager_service_endpoints = config.get("secrets_manager_service_endpoints") or "public-and-private"
secret_group_name = config.get("secret_group_name") or "vpn-certificates"
secret_group_description = config.get("secret_group_description") or "Certificate group for VPN client-to-site authentication"

# Certificate Configuration
org_name = config.get("org_name") or "MyOrganization"
country_code = config.get("country_code") or "US"
state_province = config.get("state_province") or "Texas"
locality = config.get("locality") or "Austin"
ca_common_name = config.get("ca_common_name") or "VPN CA"
server_common_name = config.get("server_common_name") or "VPN Server"
client_common_name = config.get("client_common_name") or "VPN Client"

# Certificate Validity Configuration
ca_validity_days = config.get_int("ca_validity_days") or 3650  # 10 years
cert_validity_days = config.get_int("cert_validity_days") or 365  # 1 year
key_size = config.get_int("key_size") or 2048

# Secret Names Configuration
ca_cert_secret_name = config.get("ca_cert_secret_name") or "vpn-ca-certificate"
ca_key_secret_name = config.get("ca_key_secret_name") or "vpn-ca-private-key"
server_cert_secret_name = config.get("server_cert_secret_name") or "vpn-server-certificate"
server_key_secret_name = config.get("server_key_secret_name") or "vpn-server-private-key"
client_cert_secret_name = config.get("client_cert_secret_name") or "vpn-client-certificate"
client_key_secret_name = config.get("client_key_secret_name") or "vpn-client-private-key"

# Tags Configuration
default_tags = ["vpn", "certificates", "pulumi"]
try:
    custom_tags_config = config.get("custom_tags")
    if custom_tags_config:
        # Parse JSON string if provided as JSON
        import json
        if isinstance(custom_tags_config, str):
            custom_tags = json.loads(custom_tags_config)
        else:
            custom_tags = custom_tags_config
    else:
        custom_tags = []
except (json.JSONDecodeError, ValueError):
    custom_tags = []

all_tags = default_tags + custom_tags

# Optional Features
export_certificates = config.get_bool("export_certificates") or False
enable_debug_output = config.get_bool("enable_debug_output") or False

# Get resource group if not provided directly
if not resource_group_id:
    # Look up resource group by name
    try:
        resource_groups = ibm.get_resource_group(name=resource_group_name)
        resource_group_id = resource_groups.id
        print(f"Using resource group: {resource_group_name} (ID: {resource_group_id})")
    except Exception as e:
        raise Exception(f"Could not find resource group '{resource_group_name}'. Please specify resource_group_id or ensure resource_group_name exists.")

# Validate resource group ID format (should be a GUID)
if resource_group_id and len(resource_group_id) != 32:
    raise Exception(f"Invalid resource_group_id format. Expected 32-character GUID, got: {resource_group_id}")

print(f"Using resource group ID: {resource_group_id}")
print(f"Deploying to region: {region}")

def generate_private_key():
    """Generate an RSA private key with configurable key size"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

def create_certificate_subject(common_name):
    """Create a certificate subject with configurable attributes"""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def create_ca_certificate(private_key):
    """Create a self-signed CA certificate with configurable parameters"""
    subject = issuer = create_certificate_subject(ca_common_name)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=ca_validity_days)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256())
    
    return cert

def create_server_certificate(ca_private_key, ca_cert):
    """Create a server certificate signed by the CA with configurable parameters"""
    server_private_key = generate_private_key()
    subject = create_certificate_subject(server_common_name)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=cert_validity_days)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    return server_private_key, cert

def create_client_certificate(ca_private_key, ca_cert):
    """Create a client certificate signed by the CA with configurable parameters"""
    client_private_key = generate_private_key()
    subject = create_certificate_subject(client_common_name)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=cert_validity_days)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    return client_private_key, cert

# Debug output
if enable_debug_output:
    print(f"Configuration Summary:")
    print(f"  Region: {region}")
    print(f"  Resource Group: {resource_group_name}")
    print(f"  Secrets Manager: {secrets_manager_name}")
    print(f"  Key Size: {key_size} bits")
    print(f"  CA Validity: {ca_validity_days} days")
    print(f"  Cert Validity: {cert_validity_days} days")
    print(f"  Organization: {org_name}")

# Generate certificates
if enable_debug_output:
    print("Generating certificates...")

ca_private_key = generate_private_key()
ca_cert = create_ca_certificate(ca_private_key)
server_private_key, server_cert = create_server_certificate(ca_private_key, ca_cert)
client_private_key, client_cert = create_client_certificate(ca_private_key, ca_cert)

# Convert to PEM format
ca_private_key_pem = ca_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

server_private_key_pem = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

client_private_key_pem = client_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

# Create IBM Cloud Secrets Manager instance
secrets_manager_opts = pulumi.ResourceOptions(provider=ibm_provider) if ibm_provider else None

secrets_manager = ibm.ResourceInstance(
    "vpn-secrets-manager",
    name="vpn-secrets-manager",
    service="secrets-manager",
    plan="standard",
    location=region,
    resource_group_id=resource_group_id,
    #service_endpoints=secrets_manager_service_endpoints,
    parameters={
        "allowed_network" : secrets_manager_service_endpoints,    },
    tags=["vpn", "certificates", "pulumi"],
    opts=secrets_manager_opts
)

# Wait for the Secrets Manager instance to be ready
secrets_manager_guid = secrets_manager.guid
print(secrets_manager_guid)

# Create secret group for VPN certificates
secret_group = ibm.SmSecretGroup(
    "vpn-cert-group",
    instance_id=secrets_manager_guid,
    region=region,
    name="vpn-certificates",
    description="Certificate group for VPN client-to-site authentication"
)

# Store CA certificate
ca_cert_secret = ibm.SmArbitrarySecret(
    "ca-certificate",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=ca_cert_secret_name,
    description=f"VPN CA Certificate for {org_name} - Valid for {ca_validity_days} days",
    payload=ca_cert_pem,

)

# Store CA private key
ca_key_secret = ibm.SmArbitrarySecret(
    "ca-private-key",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=ca_key_secret_name,
    description=f"VPN CA Private Key for {org_name} - {key_size}-bit RSA",
    payload=ca_private_key_pem
)

# Store server certificate
server_cert_secret = ibm.SmArbitrarySecret(
    "server-certificate",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=server_cert_secret_name,
    description=f"VPN Server Certificate for {server_common_name} - Valid for {cert_validity_days} days",
    payload=server_cert_pem
)

# Store server private key
server_key_secret = ibm.SmArbitrarySecret(
    "server-private-key",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=server_key_secret_name,
    description=f"VPN Server Private Key for {server_common_name} - {key_size}-bit RSA",
    payload=server_private_key_pem,
)

# Store client certificate
client_cert_secret = ibm.SmArbitrarySecret(
    "client-certificate",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=client_cert_secret_name,
    description=f"VPN Client Certificate for {client_common_name} - Valid for {cert_validity_days} days",
    payload=client_cert_pem
)

# Store client private key
client_key_secret = ibm.SmArbitrarySecret(
    "client-private-key",
    instance_id=secrets_manager_guid,
    region=region,
    secret_group_id=secret_group.secret_group_id,
    name=client_key_secret_name,
    description=f"VPN Client Private Key for {client_common_name} - {key_size}-bit RSA",
    payload=client_private_key_pem
)

# Export important values
pulumi.export("secrets_manager_guid", secrets_manager.guid)
pulumi.export("secrets_manager_crn", secrets_manager.crn)
pulumi.export("secrets_manager_id", secrets_manager.id)
pulumi.export("secrets_manager_name", secrets_manager_name)
pulumi.export("secret_group_id", secret_group.secret_group_id)
pulumi.export("secret_group_name", secret_group_name)

# Export secret IDs for reference
pulumi.export("ca_certificate_id", ca_cert_secret.secret_id)
pulumi.export("ca_private_key_id", ca_key_secret.secret_id)
pulumi.export("server_certificate_id", server_cert_secret.secret_id)
pulumi.export("server_private_key_id", server_key_secret.secret_id)
pulumi.export("client_certificate_id", client_cert_secret.secret_id)
pulumi.export("client_private_key_id", client_key_secret.secret_id)

# Export certificate information (for reference)
pulumi.export("certificate_info", {
    "organization": org_name,
    "country": country_code,
    "state_province": state_province,
    "locality": locality,
    "ca_common_name": ca_common_name,
    "server_common_name": server_common_name,
    "client_common_name": client_common_name,
    "key_size_bits": key_size,
    "ca_validity_days": ca_validity_days,
    "cert_validity_days": cert_validity_days,
    "secrets_manager_plan": secrets_manager_plan,
    "service_endpoints": secrets_manager_service_endpoints
})

# Export secret names for easy reference
pulumi.export("secret_names", {
    "ca_certificate": ca_cert_secret_name,
    "ca_private_key": ca_key_secret_name,
    "server_certificate": server_cert_secret_name,
    "server_private_key": server_key_secret_name,
    "client_certificate": client_cert_secret_name,
    "client_private_key": client_key_secret_name
})

# Export CRNs for VPN configuration
pulumi.export("certificate_crns", {
    "ca_certificate": ca_cert_secret.crn,
    "server_certificate": server_cert_secret.crn,
    "client_certificate": client_cert_secret.crn
})

# Conditionally export certificates for immediate use
if export_certificates:
    pulumi.export("ca_certificate_pem", ca_cert_pem)
    pulumi.export("server_certificate_pem", server_cert_pem)
    pulumi.export("client_certificate_pem", client_cert_pem)
    
    if enable_debug_output:
        print("Warning: Certificate export is enabled. Private keys will be visible in stack outputs.")

if enable_debug_output:
    print("Deployment completed successfully!")
    print(f"Secrets Manager: {secrets_manager_name}")
    print(f"Secret Group: {secret_group_name}")
pulumi.export("server_certificate_id", server_cert_secret.secret_id)
pulumi.export("client_certificate_id", client_cert_secret.secret_id)

# Export certificate details for verification
pulumi.export("ca_certificate_pem", ca_cert_pem)
pulumi.export("server_certificate_pem", server_cert_pem)
pulumi.export("client_certificate_pem", client_cert_pem)