#!/usr/bin/env python3
"""
IAM Permission Auditor - Standalone Script
==========================================
A standalone version of the IAM audit script that can be run directly
from the command line without Lambda.

Usage:
    python iam_audit_standalone.py --help
    python iam_audit_standalone.py --audit-all --threshold 90
    python iam_audit_standalone.py --audit-role TestRole-EC2Admin
    python iam_audit_standalone.py --audit-all --output report.json
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone
from typing import Optional
import boto3

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lambda_function import (
    IAMPermissionAuditor,
    EntityType,
    save_report_to_s3,
    get_cross_account_session,
    logger
)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='IAM Permission Auditor - Identify unused IAM permissions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit all roles and users
  python iam_audit_standalone.py --audit-all

  # Audit with custom threshold
  python iam_audit_standalone.py --audit-all --threshold 60

  # Audit a specific role
  python iam_audit_standalone.py --audit-role MyRoleName

  # Audit a specific user
  python iam_audit_standalone.py --audit-user MyUserName

  # Save output to file
  python iam_audit_standalone.py --audit-all --output report.json

  # Audit only roles matching a pattern
  python iam_audit_standalone.py --audit-roles --filter "Test"

  # Upload report to S3
  python iam_audit_standalone.py --audit-all --s3-bucket my-audit-bucket

  # Cross-account audit
  python iam_audit_standalone.py --audit-all --cross-account 123456789012 --role-name AuditRole
        """
    )
    
    # Audit scope options
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        '--audit-all',
        action='store_true',
        help='Audit all IAM roles and users'
    )
    scope_group.add_argument(
        '--audit-roles',
        action='store_true',
        help='Audit all IAM roles only'
    )
    scope_group.add_argument(
        '--audit-users',
        action='store_true',
        help='Audit all IAM users only'
    )
    scope_group.add_argument(
        '--audit-role',
        metavar='ROLE_NAME',
        help='Audit a specific IAM role by name'
    )
    scope_group.add_argument(
        '--audit-user',
        metavar='USER_NAME',
        help='Audit a specific IAM user by name'
    )
    scope_group.add_argument(
        '--audit-arn',
        metavar='ARN',
        help='Audit a specific IAM entity by ARN'
    )
    
    # Configuration options
    parser.add_argument(
        '--threshold', '-t',
        type=int,
        default=90,
        help='Number of days to consider a service unused (default: 90)'
    )
    parser.add_argument(
        '--filter', '-f',
        metavar='PATTERN',
        help='Filter roles/users by name pattern'
    )
    parser.add_argument(
        '--include-service-roles',
        action='store_true',
        help='Include AWS service-linked roles in audit'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        metavar='FILE',
        help='Save report to JSON file'
    )
    parser.add_argument(
        '--s3-bucket',
        metavar='BUCKET',
        help='Upload report to S3 bucket'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'summary', 'detailed'],
        default='summary',
        help='Output format (default: summary)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress output'
    )
    
    # Cross-account options
    parser.add_argument(
        '--cross-account',
        metavar='ACCOUNT_ID',
        action='append',
        help='Cross-account ID to audit (can be specified multiple times)'
    )
    parser.add_argument(
        '--role-name',
        default='IAMAuditCrossAccountRole',
        help='Role name to assume for cross-account access'
    )
    parser.add_argument(
        '--external-id',
        help='External ID for cross-account role assumption'
    )
    
    # AWS options
    parser.add_argument(
        '--profile',
        help='AWS profile to use'
    )
    parser.add_argument(
        '--region',
        help='AWS region'
    )
    
    return parser.parse_args()


def print_summary(report: dict, detailed: bool = False) -> None:
    """Print a human-readable summary of the audit report."""
    summary = report['summary']
    
    print("\n" + "=" * 70)
    print("IAM PERMISSION AUDIT REPORT")
    print("=" * 70)
    print(f"\nReport ID: {report['report_id']}")
    print(f"Generated: {report['generated_at']}")
    print(f"Environment: {report['environment']}")
    print(f"Threshold: {report['threshold_days']} days")
    print(f"Accounts Analyzed: {', '.join(report['accounts_analyzed'])}")
    
    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    print(f"Total Entities Audited: {summary['total_entities_audited']}")
    print(f"  - Roles: {summary['total_roles']}")
    print(f"  - Users: {summary['total_users']}")
    print(f"\nEntities with Unused Permissions: {summary['entities_with_unused_permissions']}")
    print(f"Total Unused Services Found: {summary['total_unused_services']}")
    print(f"Total Services Granted: {summary['total_services_granted']}")
    print(f"Average Potential Reduction: {summary['average_potential_reduction_percent']:.1f}%")
    
    print("\n" + "-" * 70)
    print("TOP 10 ENTITIES BY UNUSED PERMISSIONS")
    print("-" * 70)
    
    for i, entity in enumerate(summary['top_10_by_unused_services'], 1):
        print(f"\n{i}. {entity['entity_name']} ({entity['entity_type']})")
        print(f"   Unused Services: {entity['unused_count']}")
        print(f"   Potential Reduction: {entity['reduction_percent']:.1f}%")
    
    if detailed:
        print("\n" + "-" * 70)
        print("DETAILED ENTITY BREAKDOWN")
        print("-" * 70)
        
        for entity in report['entities']:
            if entity['unused_services_count'] > 0:
                print(f"\n{'=' * 50}")
                print(f"{entity['entity_type']}: {entity['entity_name']}")
                print(f"ARN: {entity['entity_arn']}")
                print(f"Created: {entity['creation_date']}")
                print(f"Services Granted: {entity['total_services_granted']}")
                print(f"Unused Services: {entity['unused_services_count']}")
                print(f"Used Services: {entity['used_services_count']}")
                print(f"Potential Reduction: {entity['potential_policy_reduction_percent']:.1f}%")
                
                print("\nUnused Services:")
                for svc in entity['unused_services'][:20]:  # Limit to 20
                    days = svc.get('days_since_access')
                    if days is not None:
                        print(f"  - {svc['service_name']} ({svc['service_namespace']}): "
                              f"Last accessed {days} days ago")
                    else:
                        print(f"  - {svc['service_name']} ({svc['service_namespace']}): "
                              f"NEVER accessed")
                
                if len(entity['unused_services']) > 20:
                    print(f"  ... and {len(entity['unused_services']) - 20} more")
    
    print("\n" + "-" * 70)
    print("RECOMMENDATIONS")
    print("-" * 70)
    
    for rec in report['recommendations']:
        print(f"\n• {rec}")
    
    print("\n" + "=" * 70)
    print("⚠️  WARNING: Do NOT automatically remove permissions!")
    print("    Review each finding and test changes in a non-production environment.")
    print("=" * 70 + "\n")


def main():
    """Main entry point for standalone script."""
    args = parse_arguments()
    
    # Configure logging
    if args.quiet:
        logger.setLevel('WARNING')
    
    # Create boto3 session
    session_kwargs = {}
    if args.profile:
        session_kwargs['profile_name'] = args.profile
    if args.region:
        session_kwargs['region_name'] = args.region
    
    session = boto3.Session(**session_kwargs) if session_kwargs else None
    
    # Initialize auditor
    auditor = IAMPermissionAuditor(
        session=session,
        threshold_days=args.threshold
    )
    
    all_entities = []
    accounts_analyzed = [auditor.account_id]
    
    # Perform audit based on scope
    try:
        if args.audit_all:
            print(f"Auditing all IAM roles and users in account {auditor.account_id}...")
            all_entities.extend(
                auditor.audit_all_roles(
                    filter_pattern=args.filter,
                    exclude_service_roles=not args.include_service_roles
                )
            )
            all_entities.extend(auditor.audit_all_users())
            
        elif args.audit_roles:
            print(f"Auditing all IAM roles in account {auditor.account_id}...")
            all_entities.extend(
                auditor.audit_all_roles(
                    filter_pattern=args.filter,
                    exclude_service_roles=not args.include_service_roles
                )
            )
            
        elif args.audit_users:
            print(f"Auditing all IAM users in account {auditor.account_id}...")
            all_entities.extend(auditor.audit_all_users())
            
        elif args.audit_role:
            print(f"Auditing IAM role: {args.audit_role}...")
            role_arn = f"arn:aws:iam::{auditor.account_id}:role/{args.audit_role}"
            result = auditor.audit_specific_entity(role_arn)
            all_entities.append(result)
            
        elif args.audit_user:
            print(f"Auditing IAM user: {args.audit_user}...")
            user_arn = f"arn:aws:iam::{auditor.account_id}:user/{args.audit_user}"
            result = auditor.audit_specific_entity(user_arn)
            all_entities.append(result)
            
        elif args.audit_arn:
            print(f"Auditing IAM entity: {args.audit_arn}...")
            result = auditor.audit_specific_entity(args.audit_arn)
            all_entities.append(result)
        
        # Cross-account audits
        if args.cross_account:
            for account_id in args.cross_account:
                print(f"\nAuditing cross-account: {account_id}...")
                try:
                    cross_session = get_cross_account_session(
                        account_id=account_id,
                        role_name=args.role_name,
                        external_id=args.external_id
                    )
                    cross_auditor = IAMPermissionAuditor(
                        session=cross_session,
                        threshold_days=args.threshold
                    )
                    
                    if args.audit_all or args.audit_roles:
                        all_entities.extend(
                            cross_auditor.audit_all_roles(
                                filter_pattern=args.filter,
                                exclude_service_roles=not args.include_service_roles
                            )
                        )
                    
                    if args.audit_all or args.audit_users:
                        all_entities.extend(cross_auditor.audit_all_users())
                    
                    accounts_analyzed.append(account_id)
                    
                except Exception as e:
                    print(f"ERROR: Failed to audit account {account_id}: {e}")
        
        # Generate report
        report = auditor.generate_report(all_entities, accounts_analyzed)
        report_dict = {
            'report_id': report.report_id,
            'generated_at': report.generated_at,
            'environment': report.environment,
            'threshold_days': report.threshold_days,
            'accounts_analyzed': report.accounts_analyzed,
            'summary': report.summary,
            'entities': report.entities,
            'recommendations': report.recommendations
        }
        
        # Output results
        if args.format == 'json':
            print(json.dumps(report_dict, indent=2, default=str))
        elif args.format == 'detailed':
            print_summary(report_dict, detailed=True)
        else:
            print_summary(report_dict, detailed=False)
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report_dict, f, indent=2, default=str)
            print(f"\nReport saved to: {args.output}")
        
        # Upload to S3 if requested
        if args.s3_bucket:
            s3_uri = save_report_to_s3(report, args.s3_bucket)
            print(f"\nReport uploaded to: {s3_uri}")
        
        # Return exit code based on findings
        if report.summary['entities_with_unused_permissions'] > 0:
            sys.exit(1)  # Findings detected
        else:
            sys.exit(0)  # No findings
            
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == '__main__':
    main()