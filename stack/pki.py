import pulumi_tls as tls
import pulumi_ibm as ibm
from .config import Config
import pulumi


def create_pki(cfg: Config):
    ca_private_key = tls.PrivateKey("ca-private-key", algorithm="RSA", rsa_bits=4096)
    ca_cert = tls.SelfSignedCert(
        "ca-certificate",
        private_key_pem=ca_private_key.private_key_pem,
        subject={
            "common_name": f"{cfg.pki_common_name} Root CA",
            "organization": "IBM Cloud VPC",
            "organizational_unit": "PKI Infrastructure",
            "country": "US",
            "locality": "Austin",
            "province": "TX",
        },
        validity_period_hours=cfg.ca_validity_days * 24,
        is_ca_certificate=True,
        allowed_uses=["cert_signing", "crl_signing", "key_encipherment", "digital_signature"],
    )

    intermediate_private_key = tls.PrivateKey("intermediate-private-key", algorithm="RSA", rsa_bits=2048)
    intermediate_csr = tls.CertRequest(
        "intermediate-csr",
        private_key_pem=intermediate_private_key.private_key_pem,
        subject={
            "common_name": f"{cfg.pki_common_name} Intermediate CA",
            "organization": "IBM Cloud VPC",
            "organizational_unit": "Intermediate PKI",
            "country": "US",
            "locality": "Austin",
            "province": "TX",
        },
    )
    intermediate_cert = tls.LocallySignedCert(
        "intermediate-certificate",
        cert_request_pem=intermediate_csr.cert_request_pem,
        ca_private_key_pem=ca_private_key.private_key_pem,
        ca_cert_pem=ca_cert.cert_pem,
        validity_period_hours=(cfg.certificate_validity_days * 24 * 2),
        is_ca_certificate=True,
        allowed_uses=["cert_signing", "crl_signing", "key_encipherment", "digital_signature"],
    )

    server_private_key = tls.PrivateKey("server-private-key", algorithm="RSA", rsa_bits=2048)
    server_csr = tls.CertRequest(
        "server-csr",
        private_key_pem=server_private_key.private_key_pem,
        subject={
            "common_name": f"vpn-server.{cfg.region}.cloud.ibm.com",
            "organization": "IBM Cloud VPC",
            "organizational_unit": "VPN Infrastructure",
            "country": "US",
            "locality": "Austin",
            "province": "TX",
        },
        dns_names=[
            "vpn-server",
            "vpn-server.vpc.local",
            "*.vpc.local",
            f"vpn-server.{cfg.region}.cloud.ibm.com",
            f"*.{cfg.region}.cloud.ibm.com",
            "*.vpn.ibmcloud.com",
            "*.vpn.cloud.ibm.com",
        ],
        ip_addresses=["127.0.0.1"],
    )
    server_cert = tls.LocallySignedCert(
        "server-certificate",
        cert_request_pem=server_csr.cert_request_pem,
        ca_private_key_pem=intermediate_private_key.private_key_pem,
        ca_cert_pem=intermediate_cert.cert_pem,
        validity_period_hours=cfg.certificate_validity_days * 24,
        allowed_uses=["key_encipherment", "digital_signature", "server_auth"],
    )

    client_private_key = tls.PrivateKey("client-private-key", algorithm="RSA", rsa_bits=2048)
    client_csr = tls.CertRequest(
        "client-csr",
        private_key_pem=client_private_key.private_key_pem,
        subject={
            "common_name": "vpn-client-001",
            "organization": "IBM Cloud VPC",
            "organizational_unit": "VPN Clients",
            "country": "US",
            "locality": "Austin",
            "province": "TX",
        },
    )
    client_cert = tls.LocallySignedCert(
        "client-certificate",
        cert_request_pem=client_csr.cert_request_pem,
        ca_private_key_pem=intermediate_private_key.private_key_pem,
        ca_cert_pem=intermediate_cert.cert_pem,
        validity_period_hours=cfg.certificate_validity_days * 24,
        allowed_uses=["key_encipherment", "digital_signature", "client_auth"],
    )

    return {
        "ca_private_key": ca_private_key,
        "ca_cert": ca_cert,
        "intermediate_private_key": intermediate_private_key,
        "intermediate_cert": intermediate_cert,
        "server_private_key": server_private_key,
        "server_cert": server_cert,
        "client_private_key": client_private_key,
        "client_cert": client_cert,
    }


def store_certificates(instance_id, ca_group, server_group, client_group, pki):
    server_cert_chain = pulumi.Output.all(
        pki["intermediate_cert"].cert_pem,
        pki["ca_cert"].cert_pem,
    ).apply(lambda certs: f"{certs[0].strip()}\n{certs[1].strip()}")

    ca_secret = ibm.SmImportedCertificate(
        "ca-certificate-secret",
        instance_id=instance_id,
        name="vpn-root-ca-certificate",
        description="VPN Root CA Certificate for PKI infrastructure",
        secret_group_id=ca_group.secret_group_id,
        certificate=pki["ca_cert"].cert_pem,
        private_key=pki["ca_private_key"].private_key_pem,
        labels=["root-ca", "pki", "vpn"],
    )

    intermediate_secret = ibm.SmImportedCertificate(
        "intermediate-certificate-secret",
        instance_id=instance_id,
        name="vpn-intermediate-ca-certificate",
        description="VPN Intermediate CA Certificate",
        secret_group_id=ca_group.secret_group_id,
        certificate=pki["intermediate_cert"].cert_pem,
        private_key=pki["intermediate_private_key"].private_key_pem,
        intermediate=pki["ca_cert"].cert_pem,
        labels=["intermediate-ca", "pki", "vpn"],
    )

    server_secret = ibm.SmImportedCertificate(
        "server-certificate-secret",
        instance_id=instance_id,
        name="vpn-server-certificate",
        description="VPN Server Certificate with intermediate CA",
        secret_group_id=server_group.secret_group_id,
        certificate=pki["server_cert"].cert_pem,
        private_key=pki["server_private_key"].private_key_pem,
        intermediate=pki["intermediate_cert"].cert_pem,
        labels=["server", "vpn", "certificate"],
    )

    client_secret = ibm.SmImportedCertificate(
        "client-certificate-secret",
        instance_id=instance_id,
        name="vpn-client-certificate",
        description="VPN Client Certificate with full chain",
        secret_group_id=client_group.secret_group_id,
        certificate=pki["client_cert"].cert_pem,
        private_key=pki["client_private_key"].private_key_pem,
        intermediate=server_cert_chain,
        labels=["client", "vpn", "certificate"],
    )

    return {
        "ca_secret": ca_secret,
        "intermediate_secret": intermediate_secret,
        "server_secret": server_secret,
        "client_secret": client_secret,
    }

