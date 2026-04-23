"""
IAM Audit Lambda Function
Identifies unused permissions for IAM Roles and Users.

This Lambda queries iam:GenerateServiceLastAccessedDetails to identify
IAM Roles/Users with services not accessed in the last N days (default: 90).

Output: JSON report of "Unused Services per Role/User" stored in S3.
"""

import json
import os
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET', '')
ACCOUNT_NAME = os.environ.get('ACCOUNT_NAME', 'unknown')
ACCOUNT_ID = os.environ.get('ACCOUNT_ID', '')
THRESHOLD_DAYS = int(os.environ.get('THRESHOLD_DAYS', '90'))
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENABLE_NOTIFICATIONS = os.environ.get('ENABLE_NOTIFICATIONS', 'false').lower() == 'true'


class IAMAuditException(Exception):
    """Custom exception for IAM Audit errors."""
    pass


class IAMServiceAccessAuditor:
    """
    Audits IAM roles and users for unused service permissions.
    
    Uses the IAM Service Last Accessed API to identify services
    that have not been accessed within the threshold period.
    """
    
    def __init__(self, threshold_days: int = 90):
        """
        Initialize the auditor.
        
        Args:
            threshold_days: Number of days to consider a service as unused
        """
        self.iam_client = boto3.client('iam')
        self.threshold_days = threshold_days
        self.threshold_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)
        
    def _wait_for_report(self, job_id: str, max_attempts: int = 30) -> Dict[str, Any]:
        """
        Wait for a service last accessed report to be generated.
        
        Args:
            job_id: The job ID from GenerateServiceLastAccessedDetails
            max_attempts: Maximum number of polling attempts
            
        Returns:
            The completed report details
            
        Raises:
            IAMAuditException: If the report generation fails or times out
        """
        for attempt in range(max_attempts):
            try:
                response = self.iam_client.get_service_last_accessed_details(JobId=job_id)
                status = response.get('JobStatus')
                
                if status == 'COMPLETED':
                    return response
                elif status == 'FAILED':
                    error = response.get('Error', {})
                    raise IAMAuditException(
                        f"Report generation failed: {error.get('Message', 'Unknown error')}"
                    )
                    
                # Still in progress, wait and retry
                time.sleep(2)
                
            except ClientError as e:
                logger.error(f"Error getting service last accessed details: {e}")
                raise IAMAuditException(f"Failed to get report: {str(e)}")
                
        raise IAMAuditException(f"Report generation timed out after {max_attempts} attempts")
    
    def _analyze_service_access(
        self, 
        entity_arn: str, 
        entity_name: str,
        entity_type: str
    ) -> Dict[str, Any]:
        """
        Analyze service access for an IAM entity (role or user).
        
        Args:
            entity_arn: ARN of the IAM entity
            entity_name: Name of the IAM entity
            entity_type: Type of entity ('Role' or 'User')
            
        Returns:
            Dictionary containing analysis results
        """
        result = {
            'entity_arn': entity_arn,
            'entity_name': entity_name,
            'entity_type': entity_type,
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'threshold_days': self.threshold_days,
            'total_services_granted': 0,
            'unused_services': [],
            'used_services': [],
            'never_accessed_services': [],
            'error': None
        }
        
        try:
            # Generate the service last accessed report
            generate_response = self.iam_client.generate_service_last_accessed_details(
                Arn=entity_arn
            )
            job_id = generate_response['JobId']
            
            # Wait for and retrieve the report
            report = self._wait_for_report(job_id)
            
            services_accessed = report.get('ServicesLastAccessed', [])
            result['total_services_granted'] = len(services_accessed)
            
            for service in services_accessed:
                service_name = service.get('ServiceName', 'Unknown')
                service_namespace = service.get('ServiceNamespace', 'unknown')
                last_accessed = service.get('LastAuthenticated')
                
                service_info = {
                    'service_name': service_name,
                    'service_namespace': service_namespace,
                    'total_authenticated_entities': service.get('TotalAuthenticatedEntities', 0)
                }
                
                if last_accessed:
                    service_info['last_accessed'] = last_accessed.isoformat()
                    service_info['days_since_access'] = (
                        datetime.now(timezone.utc) - last_accessed
                    ).days
                    
                    if last_accessed < self.threshold_date:
                        service_info['status'] = 'UNUSED'
                        result['unused_services'].append(service_info)
                    else:
                        service_info['status'] = 'USED'
                        result['used_services'].append(service_info)
                else:
                    service_info['last_accessed'] = None
                    service_info['days_since_access'] = None
                    service_info['status'] = 'NEVER_ACCESSED'
                    result['never_accessed_services'].append(service_info)
                    
        except IAMAuditException as e:
            result['error'] = str(e)
            logger.error(f"Error analyzing {entity_type} {entity_name}: {e}")
        except ClientError as e:
            result['error'] = str(e)
            logger.error(f"AWS error analyzing {entity_type} {entity_name}: {e}")
            
        return result
    
    def audit_roles(self, role_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Audit all IAM roles for unused service permissions.
        
        Args:
            role_filter: Optional prefix to filter roles (e.g., 'iam-audit-test')
            
        Returns:
            List of analysis results for each role
        """
        results = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                
                # Skip AWS service-linked roles
                if role.get('Path', '').startswith('/aws-service-role/'):
                    logger.info(f"Skipping service-linked role: {role_name}")
                    continue
                    
                # Apply filter if specified
                if role_filter and not role_name.startswith(role_filter):
                    continue
                    
                logger.info(f"Analyzing role: {role_name}")
                result = self._analyze_service_access(
                    entity_arn=role['Arn'],
                    entity_name=role_name,
                    entity_type='Role'
                )
                results.append(result)
                
                # Rate limiting to avoid API throttling
                time.sleep(0.5)
                
        return results
    
    def audit_users(self, user_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Audit all IAM users for unused service permissions.
        
        Args:
            user_filter: Optional prefix to filter users
            
        Returns:
            List of analysis results for each user
        """
        results = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                
                # Apply filter if specified
                if user_filter and not user_name.startswith(user_filter):
                    continue
                    
                logger.info(f"Analyzing user: {user_name}")
                result = self._analyze_service_access(
                    entity_arn=user['Arn'],
                    entity_name=user_name,
                    entity_type='User'
                )
                results.append(result)
                
                # Rate limiting
                time.sleep(0.5)
                
        return results


def generate_summary(role_results: List[Dict], user_results: List[Dict]) -> Dict[str, Any]:
    """
    Generate a summary of the audit results.
    
    Args:
        role_results: List of role analysis results
        user_results: List of user analysis results
        
    Returns:
        Summary dictionary
    """
    total_roles = len(role_results)
    total_users = len(user_results)
    
    roles_with_unused = sum(
        1 for r in role_results 
        if r.get('unused_services') or r.get('never_accessed_services')
    )
    users_with_unused = sum(
        1 for u in user_results 
        if u.get('unused_services') or u.get('never_accessed_services')
    )
    
    total_unused_services = sum(
        len(r.get('unused_services', [])) + len(r.get('never_accessed_services', []))
        for r in role_results + user_results
    )
    
    # Get top entities with most unused permissions
    all_entities = role_results + user_results
    sorted_entities = sorted(
        all_entities,
        key=lambda x: len(x.get('unused_services', [])) + len(x.get('never_accessed_services', [])),
        reverse=True
    )
    
    top_unused = [
        {
            'entity_name': e['entity_name'],
            'entity_type': e['entity_type'],
            'unused_count': len(e.get('unused_services', [])),
            'never_accessed_count': len(e.get('never_accessed_services', []))
        }
        for e in sorted_entities[:10]
        if e.get('unused_services') or e.get('never_accessed_services')
    ]
    
    return {
        'total_roles_audited': total_roles,
        'total_users_audited': total_users,
        'roles_with_unused_permissions': roles_with_unused,
        'users_with_unused_permissions': users_with_unused,
        'total_unused_service_permissions': total_unused_services,
        'top_entities_with_unused_permissions': top_unused,
        'recommendation': (
            f"Found {total_unused_services} unused service permissions across "
            f"{roles_with_unused} roles and {users_with_unused} users. "
            "Consider reviewing and removing these permissions to follow "
            "the principle of least privilege."
        )
    }


def upload_report_to_s3(report: Dict[str, Any], bucket: str, key: str) -> str:
    """
    Upload the audit report to S3.
    
    Args:
        report: The audit report dictionary
        bucket: S3 bucket name
        key: S3 object key
        
    Returns:
        S3 URI of the uploaded report
    """
    s3_client = boto3.client('s3')
    
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(report, indent=2, default=str),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        s3_uri = f"s3://{bucket}/{key}"
        logger.info(f"Report uploaded to {s3_uri}")
        return s3_uri
    except ClientError as e:
        logger.error(f"Failed to upload report to S3: {e}")
        raise


def send_notification(topic_arn: str, subject: str, message: str):
    """
    Send SNS notification with audit summary.
    
    Args:
        topic_arn: SNS topic ARN
        subject: Notification subject
        message: Notification message
    """
    if not topic_arn:
        logger.info("SNS notifications disabled - no topic ARN provided")
        return
        
    sns_client = boto3.client('sns')
    
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info(f"Notification sent to {topic_arn}")
    except ClientError as e:
        logger.warning(f"Failed to send SNS notification: {e}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for IAM unused permission audit.
    
    Args:
        event: Lambda event
        context: Lambda context
        
    Returns:
        Audit results summary
    """
    logger.info(f"Starting IAM audit for account: {ACCOUNT_NAME} ({ACCOUNT_ID})")
    logger.info(f"Threshold: {THRESHOLD_DAYS} days")
    
    # Extract filters from event if provided
    role_filter = event.get('role_filter')
    user_filter = event.get('user_filter')
    audit_users = event.get('audit_users', True)
    audit_roles = event.get('audit_roles', True)
    
    # Initialize auditor
    auditor = IAMServiceAccessAuditor(threshold_days=THRESHOLD_DAYS)
    
    # Perform audits
    role_results = []
    user_results = []
    
    if audit_roles:
        logger.info("Starting role audit...")
        role_results = auditor.audit_roles(role_filter=role_filter)
        logger.info(f"Completed audit of {len(role_results)} roles")
        
    if audit_users:
        logger.info("Starting user audit...")
        user_results = auditor.audit_users(user_filter=user_filter)
        logger.info(f"Completed audit of {len(user_results)} users")
    
    # Generate summary
    summary = generate_summary(role_results, user_results)
    
    # Build complete report
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    report = {
        'report_metadata': {
            'report_id': f"iam-audit-{ACCOUNT_NAME}-{timestamp}",
            'account_id': ACCOUNT_ID,
            'account_name': ACCOUNT_NAME,
            'environment': ENVIRONMENT,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'threshold_days': THRESHOLD_DAYS,
            'lambda_request_id': context.aws_request_id if context else 'local'
        },
        'summary': summary,
        'role_details': role_results,
        'user_details': user_results
    }
    
    # Upload to S3 if bucket is configured
    s3_uri = None
    if REPORTS_BUCKET:
        report_key = f"iam-audit-reports/{ACCOUNT_NAME}/{timestamp}/full-report.json"
        s3_uri = upload_report_to_s3(report, REPORTS_BUCKET, report_key)
        
        # Also upload a summary report
        summary_key = f"iam-audit-reports/{ACCOUNT_NAME}/{timestamp}/summary.json"
        upload_report_to_s3(
            {'report_metadata': report['report_metadata'], 'summary': summary},
            REPORTS_BUCKET,
            summary_key
        )
        
        # Upload latest report reference
        latest_key = f"iam-audit-reports/{ACCOUNT_NAME}/latest.json"
        upload_report_to_s3(
            {
                'latest_report': report_key,
                'latest_summary': summary_key,
                'generated_at': report['report_metadata']['generated_at']
            },
            REPORTS_BUCKET,
            latest_key
        )
    
    # Send notification if enabled
    if ENABLE_NOTIFICATIONS and SNS_TOPIC_ARN:
        notification_message = (
            f"IAM Audit Report - {ACCOUNT_NAME}\n\n"
            f"Account ID: {ACCOUNT_ID}\n"
            f"Threshold: {THRESHOLD_DAYS} days\n\n"
            f"Summary:\n"
            f"- Roles audited: {summary['total_roles_audited']}\n"
            f"- Users audited: {summary['total_users_audited']}\n"
            f"- Roles with unused permissions: {summary['roles_with_unused_permissions']}\n"
            f"- Users with unused permissions: {summary['users_with_unused_permissions']}\n"
            f"- Total unused service permissions: {summary['total_unused_service_permissions']}\n\n"
        )
        if s3_uri:
            notification_message += f"Full report: {s3_uri}\n"
            
        send_notification(
            SNS_TOPIC_ARN,
            f"IAM Audit Report - {ACCOUNT_NAME}",
            notification_message
        )
    
    # Return response
    response = {
        'statusCode': 200,
        'body': {
            'message': 'IAM audit completed successfully',
            'account': ACCOUNT_NAME,
            'summary': summary,
            'report_location': s3_uri
        }
    }
    
    logger.info(f"Audit complete. Summary: {json.dumps(summary, indent=2)}")
    
    return response