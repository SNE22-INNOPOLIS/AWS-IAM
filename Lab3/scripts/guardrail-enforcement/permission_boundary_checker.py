"""
Custom AWS Config Rule Lambda for IAM Role Permission Boundaries
Checks if IAM roles have the required permission boundary attached.
"""

import json
import os
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PERMISSION_BOUNDARY_ARN = os.environ.get('PERMISSION_BOUNDARY_ARN', '')

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


def evaluate_compliance(configuration_item):
    """Evaluate compliance of a single IAM role."""
    resource_id = configuration_item['resourceId']
    resource_arn = configuration_item['ARN']

    # Skip excluded roles
    if is_excluded_role(resource_id):
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f'Role {resource_id} is excluded from permission boundary enforcement',
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': resource_id
        }

    try:
        iam = boto3.client('iam')
        role = iam.get_role(RoleName=resource_id)
        current_boundary = role['Role'].get('PermissionsBoundary', {}).get('PermissionsBoundaryArn')

        if current_boundary == PERMISSION_BOUNDARY_ARN:
            return {
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': resource_id
            }
        else:
            return {
                'ComplianceType': 'NON_COMPLIANT',
                'Annotation': f'Role {resource_id} does not have the required permission boundary. Expected: {PERMISSION_BOUNDARY_ARN}, Found: {current_boundary}',
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': resource_id
            }

    except ClientError as e:
        logger.error(f"Error evaluating role {resource_id}: {str(e)}")
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f'Error evaluating role {resource_id}: {str(e)}',
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': resource_id
        }


def lambda_handler(event, context):
    """AWS Config custom rule Lambda handler."""
    logger.info(f"Received event: {json.dumps(event)}")

    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']

    # Only evaluate IAM roles
    if configuration_item['resourceType'] != 'AWS::IAM::Role':
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f'Resource type {configuration_item["resourceType"]} is not applicable for this rule'
        }

    evaluation = evaluate_compliance(configuration_item)

    # Send evaluation to AWS Config
    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=event['resultToken']
    )

    logger.info(f"Evaluation result: {evaluation}")
    return evaluation