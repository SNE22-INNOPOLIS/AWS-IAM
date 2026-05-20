"""
Guardrail Enforcement Lambda
Automatically attaches permission boundaries to new IAM roles/users.
"""

import json
import os
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PERMISSION_BOUNDARY_ARN = os.environ.get('PERMISSION_BOUNDARY_ARN', '')
ACCOUNT_ID = os.environ.get('ACCOUNT_ID', '')
ENABLE_REMEDIATION = os.environ.get('ENABLE_REMEDIATION', 'true').lower() == 'true'
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')

# Roles to exclude from enforcement
EXCLUDED_ROLE_PREFIXES = [
    'iam-guardrails-',
    'AWSServiceRole',
    'aws-service-role',
    'OrganizationAccountAccessRole',
    'stacksets-exec-'
]

EXCLUDED_ROLE_SUFFIXES = [
    '-breakglass-role'
]


def is_excluded_role(role_name: str) -> bool:
    """Check if role should be excluded from enforcement."""
    for prefix in EXCLUDED_ROLE_PREFIXES:
        if role_name.startswith(prefix):
            return True
    for suffix in EXCLUDED_ROLE_SUFFIXES:
        if role_name.endswith(suffix):
            return True
    return False


def send_notification(subject: str, message: str):
    """Send SNS notification."""
    if not SNS_TOPIC_ARN:
        return
    
    try:
        sns = boto3.client('sns')
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject limit
            Message=message
        )
        logger.info(f"Notification sent: {subject}")
    except ClientError as e:
        logger.warning(f"Failed to send notification: {e}")


def attach_permission_boundary_to_role(role_name: str) -> dict:
    """Attach permission boundary to IAM role."""
    iam = boto3.client('iam')
    result = {
        'role_name': role_name,
        'action': 'none',
        'success': False,
        'message': ''
    }
    
    try:
        # Get current role info
        role = iam.get_role(RoleName=role_name)
        current_boundary = role['Role'].get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')
        
        if current_boundary == PERMISSION_BOUNDARY_ARN:
            result['action'] = 'already_compliant'
            result['success'] = True
            result['message'] = f"Role {role_name} already has correct permission boundary"
            logger.info(result['message'])
            return result
        
        if ENABLE_REMEDIATION:
            iam.put_role_permissions_boundary(
                RoleName=role_name,
                PermissionsBoundary=PERMISSION_BOUNDARY_ARN
            )
            result['action'] = 'boundary_attached'
            result['success'] = True
            result['message'] = f"Permission boundary attached to role {role_name}"
            logger.info(result['message'])
            
            # Send notification
            send_notification(
                f"Guardrail Enforced: {role_name}",
                f"Permission boundary was automatically attached to IAM role: {role_name}\n"
                f"Boundary ARN: {PERMISSION_BOUNDARY_ARN}"
            )
        else:
            result['action'] = 'alert_only'
            result['success'] = True
            result['message'] = f"Role {role_name} missing permission boundary (remediation disabled)"
            logger.warning(result['message'])
            
            send_notification(
                f"Guardrail Violation: {role_name}",
                f"IAM role created without permission boundary: {role_name}\n"
                f"Automatic remediation is disabled."
            )
            
    except ClientError as e:
        result['action'] = 'error'
        result['message'] = f"Error processing role {role_name}: {str(e)}"
        logger.error(result['message'])
        
    return result


def attach_permission_boundary_to_user(user_name: str) -> dict:
    """Attach permission boundary to IAM user."""
    iam = boto3.client('iam')
    result = {
        'user_name': user_name,
        'action': 'none',
        'success': False,
        'message': ''
    }
    
    try:
        user = iam.get_user(UserName=user_name)
        current_boundary = user['User'].get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')
        
        if current_boundary == PERMISSION_BOUNDARY_ARN:
            result['action'] = 'already_compliant'
            result['success'] = True
            result['message'] = f"User {user_name} already has correct permission boundary"
            logger.info(result['message'])
            return result
        
        if ENABLE_REMEDIATION:
            iam.put_user_permissions_boundary(
                UserName=user_name,
                PermissionsBoundary=PERMISSION_BOUNDARY_ARN
            )
            result['action'] = 'boundary_attached'
            result['success'] = True
            result['message'] = f"Permission boundary attached to user {user_name}"
            logger.info(result['message'])
            
            send_notification(
                f"Guardrail Enforced: {user_name}",
                f"Permission boundary was automatically attached to IAM user: {user_name}\n"
                f"Boundary ARN: {PERMISSION_BOUNDARY_ARN}"
            )
        else:
            result['action'] = 'alert_only'
            result['success'] = True
            result['message'] = f"User {user_name} missing permission boundary (remediation disabled)"
            logger.warning(result['message'])
            
            send_notification(
                f"Guardrail Violation: {user_name}",
                f"IAM user created without permission boundary: {user_name}\n"
                f"Automatic remediation is disabled."
            )
            
    except ClientError as e:
        result['action'] = 'error'
        result['message'] = f"Error processing user {user_name}: {str(e)}"
        logger.error(result['message'])
        
    return result


def lambda_handler(event, context):
    """Lambda handler for guardrail enforcement."""
    logger.info(f"Received event: {json.dumps(event)}")
    
    results = []
    
    # Handle EventBridge events from CloudTrail
    if 'detail' in event:
        detail = event['detail']
        event_name = detail.get('eventName', '')
        
        if event_name == 'CreateRole':
            role_name = detail.get('requestParameters', {}).get('roleName')
            if role_name:
                if is_excluded_role(role_name):
                    logger.info(f"Skipping excluded role: {role_name}")
                    results.append({
                        'role_name': role_name,
                        'action': 'excluded',
                        'success': True,
                        'message': f"Role {role_name} is excluded from enforcement"
                    })
                else:
                    results.append(attach_permission_boundary_to_role(role_name))
                    
        elif event_name == 'CreateUser':
            user_name = detail.get('requestParameters', {}).get('userName')
            if user_name:
                results.append(attach_permission_boundary_to_user(user_name))
    
    # Handle direct invocation for scanning
    elif event.get('action') == 'scan_all':
        iam = boto3.client('iam')
        
        # Scan all roles
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                if not is_excluded_role(role_name):
                    results.append(attach_permission_boundary_to_role(role_name))
        
        # Scan all users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                results.append(attach_permission_boundary_to_user(user['UserName']))
    
    response = {
        'statusCode': 200,
        'body': {
            'message': 'Guardrail enforcement completed',
            'results': results,
            'total_processed': len(results),
            'successful': sum(1 for r in results if r.get('success', False))
        }
    }
    
    logger.info(f"Completed: {json.dumps(response['body'])}")
    return response