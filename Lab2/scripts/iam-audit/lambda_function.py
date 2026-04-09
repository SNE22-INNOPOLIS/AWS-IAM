#!/usr/bin/env python3
"""
IAM Permission Auditor - Lambda Function
=========================================
Identifies unused IAM permissions by analyzing service last accessed data.
Generates JSON reports of unused services per IAM role/user.

This script is Lambda-ready and can also be run standalone.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# =============================================================================
# Configuration
# =============================================================================


LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
UNUSED_THRESHOLD_DAYS = int(os.environ.get('UNUSED_THRESHOLD_DAYS', '90'))
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', '')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'lab')

# Account configuration (from Lab1)
SECURITY_ACCOUNT_ID = os.environ.get('SECURITY_ACCOUNT_ID', '')
WORKLOADS_ACCOUNT_ID = os.environ.get('WORKLOADS_ACCOUNT_ID', '')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', 'CrossAccountAuditRole')
CROSS_ACCOUNT_EXTERNAL_ID = os.environ.get('CROSS_ACCOUNT_EXTERNAL_ID', 'security-lab-audit')

# Derived configuration
ACCOUNTS_TO_AUDIT = [SECURITY_ACCOUNT_ID, WORKLOADS_ACCOUNT_ID] if WORKLOADS_ACCOUNT_ID else [SECURITY_ACCOUNT_ID]


# =============================================================================
# Data Classes
# =============================================================================

class EntityType(Enum):
    """IAM Entity Types"""
    ROLE = "Role"
    USER = "User"


@dataclass
class ServiceAccessInfo:
    """Information about service access"""
    service_name: str
    service_namespace: str
    last_accessed: Optional[str]
    last_accessed_region: Optional[str]
    days_since_access: Optional[int]
    total_authenticated_entities: int
    is_unused: bool


@dataclass
class EntityAuditResult:
    """Audit result for an IAM entity"""
    entity_type: str
    entity_name: str
    entity_arn: str
    account_id: str
    creation_date: str
    total_services_granted: int
    unused_services_count: int
    used_services_count: int
    unused_services: List[ServiceAccessInfo]
    used_services: List[ServiceAccessInfo]
    potential_policy_reduction_percent: float
    audit_timestamp: str


@dataclass
class AuditReport:
    """Complete audit report"""
    report_id: str
    generated_at: str
    environment: str
    threshold_days: int
    accounts_analyzed: List[str]
    summary: Dict[str, Any]
    entities: List[EntityAuditResult]
    recommendations: List[str]


# =============================================================================
# IAM Audit Class
# =============================================================================

class IAMPermissionAuditor:
    """
    Audits IAM permissions to identify unused services.
    
    Uses IAM's GenerateServiceLastAccessedDetails API to determine
    which services have not been accessed within the threshold period.
    """

    def __init__(
        self,
        session: Optional[boto3.Session] = None,
        threshold_days: int = UNUSED_THRESHOLD_DAYS
    ):
        """
        Initialize the auditor.
        
        Args:
            session: Boto3 session (uses default if not provided)
            threshold_days: Number of days to consider a service unused
        """
        self.session = session or boto3.Session()
        self.iam_client = self.session.client('iam')
        self.threshold_days = threshold_days
        self.threshold_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)
        
        # Get account info
        sts_client = self.session.client('sts')
        self.account_id = sts_client.get_caller_identity()['Account']
        
        logger.info(f"Initialized IAM Auditor for account {self.account_id}")
        logger.info(f"Threshold: {threshold_days} days (services not accessed since {self.threshold_date.date()})")

    def generate_service_last_accessed_details(self, arn: str) -> str:
        """
        Generate a report of service last accessed details for an IAM entity.
        
        Args:
            arn: ARN of the IAM role or user
            
        Returns:
            Job ID for the generated report
        """
        try:
            response = self.iam_client.generate_service_last_accessed_details(Arn=arn)
            return response['JobId']
        except ClientError as e:
            logger.error(f"Failed to generate service last accessed details for {arn}: {e}")
            raise

    def get_service_last_accessed_details(
        self,
        job_id: str,
        max_wait_seconds: int = 120
    ) -> Dict[str, Any]:
        """
        Wait for and retrieve service last accessed details.
        
        Args:
            job_id: Job ID from generate_service_last_accessed_details
            max_wait_seconds: Maximum time to wait for job completion
            
        Returns:
            Service last accessed details
        """
        start_time = time.time()
        
        while True:
            try:
                response = self.iam_client.get_service_last_accessed_details(JobId=job_id)
                job_status = response['JobStatus']
                
                if job_status == 'COMPLETED':
                    return response
                elif job_status == 'FAILED':
                    error_msg = response.get('Error', {}).get('Message', 'Unknown error')
                    raise Exception(f"Job failed: {error_msg}")
                
                # Check timeout
                if time.time() - start_time > max_wait_seconds:
                    raise TimeoutError(f"Job {job_id} did not complete within {max_wait_seconds} seconds")
                
                # Wait before polling again
                time.sleep(2)
                
            except ClientError as e:
                logger.error(f"Error getting service last accessed details: {e}")
                raise

    def analyze_entity_access(
        self,
        entity_arn: str,
        entity_name: str,
        entity_type: EntityType,
        creation_date: datetime
    ) -> EntityAuditResult:
        """
        Analyze service access for an IAM entity.
        
        Args:
            entity_arn: ARN of the entity
            entity_name: Name of the entity
            entity_type: Type of entity (Role or User)
            creation_date: When the entity was created
            
        Returns:
            EntityAuditResult with analysis
        """
        logger.info(f"Analyzing {entity_type.value}: {entity_name}")
        
        # Generate and wait for service access report
        job_id = self.generate_service_last_accessed_details(entity_arn)
        details = self.get_service_last_accessed_details(job_id)
        
        services_last_accessed = details.get('ServicesLastAccessed', [])
        
        unused_services: List[ServiceAccessInfo] = []
        used_services: List[ServiceAccessInfo] = []
        
        for service in services_last_accessed:
            service_name = service.get('ServiceName', 'Unknown')
            service_namespace = service.get('ServiceNamespace', 'unknown')
            last_authenticated = service.get('LastAuthenticated')
            last_authenticated_region = service.get('LastAuthenticatedRegion')
            total_entities = service.get('TotalAuthenticatedEntities', 0)
            
            # Determine if service is unused
            if last_authenticated:
                last_accessed_dt = last_authenticated.replace(tzinfo=timezone.utc) if last_authenticated.tzinfo is None else last_authenticated
                days_since = (datetime.now(timezone.utc) - last_accessed_dt).days
                is_unused = days_since > self.threshold_days
                last_accessed_str = last_accessed_dt.isoformat()
            else:
                # Service was never accessed
                days_since = None
                is_unused = True
                last_accessed_str = None
            
            service_info = ServiceAccessInfo(
                service_name=service_name,
                service_namespace=service_namespace,
                last_accessed=last_accessed_str,
                last_accessed_region=last_authenticated_region,
                days_since_access=days_since,
                total_authenticated_entities=total_entities,
                is_unused=is_unused
            )
            
            if is_unused:
                unused_services.append(service_info)
            else:
                used_services.append(service_info)
        
        total_services = len(services_last_accessed)
        unused_count = len(unused_services)
        
        # Calculate potential reduction
        reduction_percent = (unused_count / total_services * 100) if total_services > 0 else 0
        
        return EntityAuditResult(
            entity_type=entity_type.value,
            entity_name=entity_name,
            entity_arn=entity_arn,
            account_id=self.account_id,
            creation_date=creation_date.isoformat() if creation_date else None,
            total_services_granted=total_services,
            unused_services_count=unused_count,
            used_services_count=len(used_services),
            unused_services=[asdict(s) for s in unused_services],
            used_services=[asdict(s) for s in used_services],
            potential_policy_reduction_percent=round(reduction_percent, 2),
            audit_timestamp=datetime.now(timezone.utc).isoformat()
        )

    def audit_all_roles(
        self,
        filter_pattern: Optional[str] = None,
        exclude_service_roles: bool = True
    ) -> List[EntityAuditResult]:
        """
        Audit all IAM roles in the account.
        
        Args:
            filter_pattern: Optional pattern to filter role names
            exclude_service_roles: Whether to exclude AWS service-linked roles
            
        Returns:
            List of EntityAuditResult for each role
        """
        results = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                role_arn = role['Arn']
                creation_date = role['CreateDate']
                
                # Skip service-linked roles if requested
                if exclude_service_roles and '/aws-service-role/' in role_arn:
                    logger.debug(f"Skipping service-linked role: {role_name}")
                    continue
                
                # Apply filter if provided
                if filter_pattern and filter_pattern.lower() not in role_name.lower():
                    continue
                
                try:
                    result = self.analyze_entity_access(
                        entity_arn=role_arn,
                        entity_name=role_name,
                        entity_type=EntityType.ROLE,
                        creation_date=creation_date
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to audit role {role_name}: {e}")
                    continue
        
        return results

    def audit_all_users(self) -> List[EntityAuditResult]:
        """
        Audit all IAM users in the account.
        
        Returns:
            List of EntityAuditResult for each user
        """
        results = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                user_arn = user['Arn']
                creation_date = user['CreateDate']
                
                try:
                    result = self.analyze_entity_access(
                        entity_arn=user_arn,
                        entity_name=user_name,
                        entity_type=EntityType.USER,
                        creation_date=creation_date
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to audit user {user_name}: {e}")
                    continue
        
        return results

    def audit_specific_entity(self, entity_arn: str) -> EntityAuditResult:
        """
        Audit a specific IAM entity by ARN.
        
        Args:
            entity_arn: ARN of the role or user
            
        Returns:
            EntityAuditResult for the entity
        """
        # Determine entity type from ARN
        if ':role/' in entity_arn:
            entity_type = EntityType.ROLE
            entity_name = entity_arn.split(':role/')[-1]
            response = self.iam_client.get_role(RoleName=entity_name)
            creation_date = response['Role']['CreateDate']
        elif ':user/' in entity_arn:
            entity_type = EntityType.USER
            entity_name = entity_arn.split(':user/')[-1]
            response = self.iam_client.get_user(UserName=entity_name)
            creation_date = response['User']['CreateDate']
        else:
            raise ValueError(f"Invalid entity ARN: {entity_arn}")
        
        return self.analyze_entity_access(
            entity_arn=entity_arn,
            entity_name=entity_name,
            entity_type=entity_type,
            creation_date=creation_date
        )

    def generate_report(
        self,
        entities: List[EntityAuditResult],
        accounts_analyzed: Optional[List[str]] = None
    ) -> AuditReport:
        """
        Generate a comprehensive audit report.
        
        Args:
            entities: List of audited entities
            accounts_analyzed: List of account IDs analyzed
            
        Returns:
            AuditReport with summary and recommendations
        """
        report_id = f"iam-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        
        # Calculate summary statistics
        total_entities = len(entities)
        total_unused_services = sum(e.unused_services_count for e in entities)
        total_services = sum(e.total_services_granted for e in entities)
        
        entities_with_unused = [e for e in entities if e.unused_services_count > 0]
        avg_reduction = (
            sum(e.potential_policy_reduction_percent for e in entities_with_unused) / 
            len(entities_with_unused)
        ) if entities_with_unused else 0
        
        # Top entities by unused permissions
        top_unused = sorted(
            entities,
            key=lambda e: e.unused_services_count,
            reverse=True
        )[:10]
        
        summary = {
            "total_entities_audited": total_entities,
            "total_roles": len([e for e in entities if e.entity_type == "Role"]),
            "total_users": len([e for e in entities if e.entity_type == "User"]),
            "entities_with_unused_permissions": len(entities_with_unused),
            "total_unused_services": total_unused_services,
            "total_services_granted": total_services,
            "average_potential_reduction_percent": round(avg_reduction, 2),
            "top_10_by_unused_services": [
                {
                    "entity_name": e.entity_name,
                    "entity_type": e.entity_type,
                    "unused_count": e.unused_services_count,
                    "reduction_percent": e.potential_policy_reduction_percent
                }
                for e in top_unused
            ]
        }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(entities, summary)
        
        return AuditReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            environment=ENVIRONMENT,
            threshold_days=self.threshold_days,
            accounts_analyzed=accounts_analyzed or [self.account_id],
            summary=summary,
            entities=[asdict(e) for e in entities],
            recommendations=recommendations
        )

    def _generate_recommendations(
        self,
        entities: List[EntityAuditResult],
        summary: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations based on audit results."""
        recommendations = []
        
        # High-level recommendations
        if summary["entities_with_unused_permissions"] > 0:
            pct = (summary["entities_with_unused_permissions"] / 
                   summary["total_entities_audited"] * 100)
            recommendations.append(
                f"PRIORITY: {summary['entities_with_unused_permissions']} entities "
                f"({pct:.1f}%) have unused permissions. Review and right-size policies."
            )
        
        if summary["average_potential_reduction_percent"] > 30:
            recommendations.append(
                f"HIGH IMPACT: Average potential policy reduction is "
                f"{summary['average_potential_reduction_percent']:.1f}%. "
                "Consider implementing least-privilege policies."
            )
        
        # Specific entity recommendations
        for entity in entities:
            if entity.unused_services_count > 10:
                recommendations.append(
                    f"REVIEW: {entity.entity_type} '{entity.entity_name}' has "
                    f"{entity.unused_services_count} unused service permissions. "
                    "Consider creating a custom policy with only required services."
                )
        
        # Never-accessed services
        never_accessed_entities = [
            e for e in entities 
            if any(s.get('days_since_access') is None for s in e.unused_services)
        ]
        if never_accessed_entities:
            recommendations.append(
                f"INVESTIGATE: {len(never_accessed_entities)} entities have services "
                "that were NEVER accessed. These may be candidates for immediate removal."
            )
        
        if not recommendations:
            recommendations.append(
                "All entities appear to be using their granted permissions appropriately. "
                "Continue monitoring for changes."
            )
        
        return recommendations


# =============================================================================
# Report Storage and Notification
# =============================================================================

def save_report_to_s3(report: AuditReport, bucket_name: str) -> str:
    """
    Save the audit report to S3.
    
    Args:
        report: The audit report to save
        bucket_name: S3 bucket name
        
    Returns:
        S3 URI of the saved report
    """
    s3_client = boto3.client('s3')
    
    # Create report key with date partitioning
    date_prefix = datetime.now(timezone.utc).strftime('%Y/%m/%d')
    report_key = f"reports/{date_prefix}/{report.report_id}.json"
    
    # Convert report to JSON
    report_json = json.dumps(asdict(report), indent=2, default=str)
    
    # Upload to S3
    s3_client.put_object(
        Bucket=bucket_name,
        Key=report_key,
        Body=report_json,
        ContentType='application/json',
        ServerSideEncryption='AES256'
    )
    
    s3_uri = f"s3://{bucket_name}/{report_key}"
    logger.info(f"Report saved to {s3_uri}")
    
    return s3_uri


def send_notification(report: AuditReport, topic_arn: str, s3_uri: str) -> None:
    """
    Send SNS notification with audit summary.
    
    Args:
        report: The audit report
        topic_arn: SNS topic ARN
        s3_uri: S3 URI where report is stored
    """
    sns_client = boto3.client('sns')
    
    summary = report.summary
    
    message = f"""
IAM Permission Audit Report - {report.environment.upper()}
{'=' * 50}

Report ID: {report.report_id}
Generated: {report.generated_at}
Threshold: {report.threshold_days} days

SUMMARY
-------
• Entities Audited: {summary['total_entities_audited']}
  - Roles: {summary['total_roles']}
  - Users: {summary['total_users']}
• Entities with Unused Permissions: {summary['entities_with_unused_permissions']}
• Total Unused Services Found: {summary['total_unused_services']}
• Average Potential Reduction: {summary['average_potential_reduction_percent']:.1f}%

TOP 5 ENTITIES BY UNUSED PERMISSIONS
------------------------------------
"""
    
    for i, entity in enumerate(summary['top_10_by_unused_services'][:5], 1):
        message += f"{i}. {entity['entity_name']} ({entity['entity_type']}): "
        message += f"{entity['unused_count']} unused services "
        message += f"({entity['reduction_percent']:.1f}% reduction potential)\n"
    
    message += f"""
RECOMMENDATIONS
---------------
"""
    for rec in report.recommendations[:5]:
        message += f"• {rec}\n"
    
    message += f"""
Full report available at: {s3_uri}

---
This is an automated message from the IAM Permission Auditor.
Do NOT automatically remove permissions - review and test changes first.
"""
    
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f"[{report.environment.upper()}] IAM Audit: {summary['entities_with_unused_permissions']} entities need review",
        Message=message
    )
    
    logger.info(f"Notification sent to {topic_arn}")


# =============================================================================
# Cross-Account Support
# =============================================================================

def get_cross_account_session(
    account_id: str,
    role_name: str = CROSS_ACCOUNT_ROLE_NAME,
    external_id: str = CROSS_ACCOUNT_EXTERNAL_ID
) -> boto3.Session:
    """
    Get a session for the Workloads account using Lab1 cross-account role.
    """
    sts_client = boto3.client('sts')
    
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    logger.info(f"Assuming role {role_arn} for cross-account access")
    
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f'IAMAudit-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        ExternalId=external_id
    )
    
    credentials = response['Credentials']
    
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


# =============================================================================
# Lambda Handler
# =============================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for IAM permission auditing.
    Audits both Security Account and Workloads Account (from Lab1).
    """
    logger.info(f"Starting IAM audit with event: {json.dumps(event)}")
    
    try:
        # Parse event parameters
        report_type = event.get('report_type', 'full')
        threshold_days = event.get('threshold_days', UNUSED_THRESHOLD_DAYS)
        entity_arn = event.get('entity_arn')
        filter_pattern = event.get('filter_pattern')
        send_notification_flag = event.get('send_notification', True)
        
        # Use configured accounts from Lab1
        accounts_to_audit = event.get('audit_accounts', ACCOUNTS_TO_AUDIT)
        
        all_entities = []
        accounts_analyzed = []
        
        # =================================================================
        # Audit Security Account (current account)
        # =================================================================
        logger.info(f"Auditing Security Account: {SECURITY_ACCOUNT_ID}")
        auditor = IAMPermissionAuditor(threshold_days=threshold_days)
        accounts_analyzed.append(auditor.account_id)
        
        if report_type == 'specific' and entity_arn:
            result = auditor.audit_specific_entity(entity_arn)
            all_entities.append(result)
        elif report_type == 'roles_only':
            all_entities.extend(auditor.audit_all_roles(filter_pattern=filter_pattern))
        elif report_type == 'users_only':
            all_entities.extend(auditor.audit_all_users())
        else:
            all_entities.extend(auditor.audit_all_roles(filter_pattern=filter_pattern))
            all_entities.extend(auditor.audit_all_users())
        
        # =================================================================
        # Audit Workloads Account (cross-account from Lab1)
        # =================================================================
        if WORKLOADS_ACCOUNT_ID and WORKLOADS_ACCOUNT_ID in accounts_to_audit:
            try:
                logger.info(f"Auditing Workloads Account: {WORKLOADS_ACCOUNT_ID}")
                workloads_session = get_cross_account_session(
                    account_id=WORKLOADS_ACCOUNT_ID,
                    role_name=CROSS_ACCOUNT_ROLE_NAME,
                    external_id=CROSS_ACCOUNT_EXTERNAL_ID
                )
                workloads_auditor = IAMPermissionAuditor(
                    session=workloads_session,
                    threshold_days=threshold_days
                )
                
                if report_type != 'specific':
                    all_entities.extend(workloads_auditor.audit_all_roles(filter_pattern=filter_pattern))
                    all_entities.extend(workloads_auditor.audit_all_users())
                
                accounts_analyzed.append(WORKLOADS_ACCOUNT_ID)
                
            except Exception as e:
                logger.error(f"Failed to audit Workloads Account {WORKLOADS_ACCOUNT_ID}: {e}")
        
        # Generate report
        report = auditor.generate_report(all_entities, accounts_analyzed)
        
        # Save to S3 if configured
        s3_uri = None
        if S3_BUCKET_NAME:
            s3_uri = save_report_to_s3(report, S3_BUCKET_NAME)
        
        # Send notification if configured
        if send_notification_flag and SNS_TOPIC_ARN and s3_uri:
            send_notification(report, SNS_TOPIC_ARN, s3_uri)
        
        return {
            'statusCode': 200,
            'body': {
                'report_id': report.report_id,
                'accounts_analyzed': accounts_analyzed,
                'summary': report.summary,
                's3_uri': s3_uri,
                'recommendations': report.recommendations[:5]
            }
        }
        
    except Exception as e:
        logger.error(f"Audit failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': {
                'error': str(e)
            }
        }


# =============================================================================
# Main Entry Point (for local testing)
# =============================================================================

if __name__ == '__main__':
    # Test event for local execution
    test_event = {
        'report_type': 'full',
        'threshold_days': 90,
        'send_notification': False
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2, default=str))