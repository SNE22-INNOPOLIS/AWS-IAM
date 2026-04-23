#!/usr/bin/env python3
"""
Local runner for IAM Audit Lambda function.

This script allows testing the Lambda function locally without deploying to AWS.
It uses the same logic as the Lambda handler but can be run from the command line.

Usage:
    python local_runner.py --profile <aws-profile> --threshold-days 90
    python local_runner.py --profile security --role-filter iam-audit-test
"""

import argparse
import json
import os
import sys
from datetime import datetime

import boto3

# Add the current directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lambda_function import IAMServiceAccessAuditor, generate_summary


class MockContext:
    """Mock Lambda context for local testing."""
    aws_request_id = "local-test-" + datetime.now().strftime("%Y%m%d%H%M%S")


def main():
    parser = argparse.ArgumentParser(
        description="Local runner for IAM Audit Lambda function"
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="AWS CLI profile to use"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--threshold-days",
        type=int,
        default=90,
        help="Days threshold for unused permissions (default: 90)"
    )
    parser.add_argument(
        "--role-filter",
        help="Filter roles by prefix (e.g., 'iam-audit-test')"
    )
    parser.add_argument(
        "--user-filter",
        help="Filter users by prefix"
    )
    parser.add_argument(
        "--roles-only",
        action="store_true",
        help="Only audit roles, skip users"
    )
    parser.add_argument(
        "--users-only",
        action="store_true",
        help="Only audit users, skip roles"
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Set up boto3 session with the specified profile
    boto3.setup_default_session(
        profile_name=args.profile,
        region_name=args.region
    )
    
    # Get account info
    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()
    account_id = identity['Account']
    
    print(f"Running IAM audit for account: {account_id}")
    print(f"Profile: {args.profile}")
    print(f"Region: {args.region}")
    print(f"Threshold: {args.threshold_days} days")
    
    if args.role_filter:
        print(f"Role filter: {args.role_filter}")
    if args.user_filter:
        print(f"User filter: {args.user_filter}")
    
    print("-" * 60)
    
    # Initialize auditor
    auditor = IAMServiceAccessAuditor(threshold_days=args.threshold_days)
    
    # Perform audits
    role_results = []
    user_results = []
    
    if not args.users_only:
        print("\nAuditing IAM Roles...")
        role_results = auditor.audit_roles(role_filter=args.role_filter)
        print(f"Audited {len(role_results)} roles")
        
    if not args.roles_only:
        print("\nAuditing IAM Users...")
        user_results = auditor.audit_users(user_filter=args.user_filter)
        print(f"Audited {len(user_results)} users")
    
    # Generate summary
    summary = generate_summary(role_results, user_results)
    
    # Build report
    report = {
        'report_metadata': {
            'report_id': f"iam-audit-local-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'account_id': account_id,
            'profile': args.profile,
            'generated_at': datetime.now().isoformat(),
            'threshold_days': args.threshold_days
        },
        'summary': summary,
        'role_details': role_results,
        'user_details': user_results
    }
    
    # Output
    report_json = json.dumps(report, indent=2, default=str)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report_json)
        print(f"\nReport saved to: {args.output}")
    else:
        print("\n" + "=" * 60)
        print("AUDIT REPORT")
        print("=" * 60)
        print(report_json)
    
    # Print summary to console
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Roles audited: {summary['total_roles_audited']}")
    print(f"Users audited: {summary['total_users_audited']}")
    print(f"Roles with unused permissions: {summary['roles_with_unused_permissions']}")
    print(f"Users with unused permissions: {summary['users_with_unused_permissions']}")
    print(f"Total unused service permissions: {summary['total_unused_service_permissions']}")

    if summary['top_entities_with_unused_permissions']:
    print("\nTop entities with unused permissions:")
    for entity in summary['top_entities_with_unused_permissions']:
        print(f"  - {entity['entity_type']} '{entity['entity_name']}': "
              f"{entity['unused_count']} unused, {entity['never_accessed_count']} never accessed")

    print("\n" + summary['recommendation'])

    return report