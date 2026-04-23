
#!/usr/bin/env python3

"""
Unit tests for IAM Audit Lambda function.

Usage:
    python -m pytest test_lambda.py -v
    python test_lambda.py  # Run directly
"""

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

# Add the current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lambda_function import (
    IAMServiceAccessAuditor,
    generate_summary,
    lambda_handler,
    IAMAuditException
)


class TestIAMServiceAccessAuditor(unittest.TestCase):
    """Tests for IAMServiceAccessAuditor class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.auditor = IAMServiceAccessAuditor(threshold_days=90)
        
    @patch('lambda_function.boto3.client')
    def test_audit_roles_success(self, mock_boto_client):
        """Test successful role audit."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        # Mock list_roles paginator
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Roles': [
                    {
                        'RoleName': 'test-role',
                        'Arn': 'arn:aws:iam::123456789012:role/test-role',
                        'Path': '/'
                    }
                ]
            }
        ]
        
        # Mock generate_service_last_accessed_details
        mock_iam.generate_service_last_accessed_details.return_value = {
            'JobId': 'test-job-id'
        }
        
        # Mock get_service_last_accessed_details
        last_accessed_time = datetime.now(timezone.utc) - timedelta(days=100)
        mock_iam.get_service_last_accessed_details.return_value = {
            'JobStatus': 'COMPLETED',
            'ServicesLastAccessed': [
                {
                    'ServiceName': 'Amazon S3',
                    'ServiceNamespace': 's3',
                    'LastAuthenticated': last_accessed_time,
                    'TotalAuthenticatedEntities': 1
                },
                {
                    'ServiceName': 'Amazon EC2',
                    'ServiceNamespace': 'ec2',
                    'LastAuthenticated': None,
                    'TotalAuthenticatedEntities': 0
                }
            ]
        }
        
        # Create new auditor with mocked client
        auditor = IAMServiceAccessAuditor(threshold_days=90)
        auditor.iam_client = mock_iam
        
        results = auditor.audit_roles()
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['entity_name'], 'test-role')
        self.assertEqual(results[0]['entity_type'], 'Role')
        self.assertEqual(len(results[0]['unused_services']), 1)
        self.assertEqual(len(results[0]['never_accessed_services']), 1)
        
    @patch('lambda_function.boto3.client')
    def test_skip_service_linked_roles(self, mock_boto_client):
        """Test that service-linked roles are skipped."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Roles': [
                    {
                        'RoleName': 'AWSServiceRoleForConfig',
                        'Arn': 'arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig',
                        'Path': '/aws-service-role/config.amazonaws.com/'
                    }
                ]
            }
        ]
        
        auditor = IAMServiceAccessAuditor(threshold_days=90)
        auditor.iam_client = mock_iam
        
        results = auditor.audit_roles()
        
        self.assertEqual(len(results), 0)
        
    @patch('lambda_function.boto3.client')
    def test_role_filter(self, mock_boto_client):
        """Test role filtering by prefix."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Roles': [
                    {
                        'RoleName': 'test-role-1',
                        'Arn': 'arn:aws:iam::123456789012:role/test-role-1',
                        'Path': '/'
                    },
                    {
                        'RoleName': 'other-role',
                        'Arn': 'arn:aws:iam::123456789012:role/other-role',
                        'Path': '/'
                    }
                ]
            }
        ]
        
        mock_iam.generate_service_last_accessed_details.return_value = {
            'JobId': 'test-job-id'
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            'JobStatus': 'COMPLETED',
            'ServicesLastAccessed': []
        }
        
        auditor = IAMServiceAccessAuditor(threshold_days=90)
        auditor.iam_client = mock_iam
        
        results = auditor.audit_roles(role_filter='test-')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['entity_name'], 'test-role-1')


class TestGenerateSummary(unittest.TestCase):
    """Tests for generate_summary function."""
    
    def test_generate_summary_with_results(self):
        """Test summary generation with audit results."""
        role_results = [
            {
                'entity_name': 'role1',
                'entity_type': 'Role',
                'unused_services': [{'service_name': 's3'}],
                'never_accessed_services': [{'service_name': 'ec2'}]
            },
            {
                'entity_name': 'role2',
                'entity_type': 'Role',
                'unused_services': [],
                'never_accessed_services': []
            }
        ]
        user_results = [
            {
                'entity_name': 'user1',
                'entity_type': 'User',
                'unused_services': [{'service_name': 'dynamodb'}],
                'never_accessed_services': []
            }
        ]
        
        summary = generate_summary(role_results, user_results)
        
        self.assertEqual(summary['total_roles_audited'], 2)
        self.assertEqual(summary['total_users_audited'], 1)
        self.assertEqual(summary['roles_with_unused_permissions'], 1)
        self.assertEqual(summary['users_with_unused_permissions'], 1)
        self.assertEqual(summary['total_unused_service_permissions'], 3)
        
    def test_generate_summary_empty_results(self):
        """Test summary generation with no results."""
        summary = generate_summary([], [])
        
        self.assertEqual(summary['total_roles_audited'], 0)
        self.assertEqual(summary['total_users_audited'], 0)
        self.assertEqual(summary['roles_with_unused_permissions'], 0)
        self.assertEqual(summary['users_with_unused_permissions'], 0)
        self.assertEqual(summary['total_unused_service_permissions'], 0)


class TestLambdaHandler(unittest.TestCase):
    """Tests for lambda_handler function."""
    
    @patch.dict(os.environ, {
        'REPORTS_BUCKET': '',
        'ACCOUNT_NAME': 'test',
        'ACCOUNT_ID': '123456789012',
        'THRESHOLD_DAYS': '90',
        'ENVIRONMENT': 'test',
        'ENABLE_NOTIFICATIONS': 'false'
    })
    @patch('lambda_function.IAMServiceAccessAuditor')
    def test_lambda_handler_success(self, mock_auditor_class):
        """Test successful Lambda execution."""
        mock_auditor = MagicMock()
        mock_auditor_class.return_value = mock_auditor
        mock_auditor.audit_roles.return_value = []
        mock_auditor.audit_users.return_value = []
        
        mock_context = MagicMock()
        mock_context.aws_request_id = 'test-request-id'
        
        event = {}
        response = lambda_handler(event, mock_context)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertIn('summary', response['body'])
        
    @patch.dict(os.environ, {
        'REPORTS_BUCKET': '',
        'ACCOUNT_NAME': 'test',
        'ACCOUNT_ID': '123456789012',
        'THRESHOLD_DAYS': '90',
        'ENVIRONMENT': 'test',
        'ENABLE_NOTIFICATIONS': 'false'
    })
    @patch('lambda_function.IAMServiceAccessAuditor')
    def test_lambda_handler_with_filters(self, mock_auditor_class):
        """Test Lambda execution with role/user filters."""
        mock_auditor = MagicMock()
        mock_auditor_class.return_value = mock_auditor
        mock_auditor.audit_roles.return_value = []
        mock_auditor.audit_users.return_value = []
        
        mock_context = MagicMock()
        mock_context.aws_request_id = 'test-request-id'
        
        event = {
            'role_filter': 'test-',
            'user_filter': 'admin-',
            'audit_users': True,
            'audit_roles': True
        }
        
        response = lambda_handler(event, mock_context)
        
        self.assertEqual(response['statusCode'], 200)
        mock_auditor.audit_roles.assert_called_once_with(role_filter='test-')
        mock_auditor.audit_users.assert_called_once_with(user_filter='admin-')


class TestWaitForReport(unittest.TestCase):
    """Tests for _wait_for_report method."""
    
    @patch('lambda_function.boto3.client')
    def test_wait_for_report_success(self, mock_boto_client):
        """Test successful report wait."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        mock_iam.get_service_last_accessed_details.return_value = {
            'JobStatus': 'COMPLETED',
            'ServicesLastAccessed': []
        }
        
        auditor = IAMServiceAccessAuditor(threshold_days=90)
        auditor.iam_client = mock_iam
        
        result = auditor._wait_for_report('test-job-id')
        
        self.assertEqual(result['JobStatus'], 'COMPLETED')
        
    @patch('lambda_function.boto3.client')
    def test_wait_for_report_failed(self, mock_boto_client):
        """Test report generation failure."""
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam
        
        mock_iam.get_service_last_accessed_details.return_value = {
            'JobStatus': 'FAILED',
            'Error': {'Message': 'Test error'}
        }
        
        auditor = IAMServiceAccessAuditor(threshold_days=90)
        auditor.iam_client = mock_iam
        
        with self.assertRaises(IAMAuditException):
            auditor._wait_for_report('test-job-id')


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestIAMServiceAccessAuditor))
    suite.addTests(loader.loadTestsFromTestCase(TestGenerateSummary))
    suite.addTests(loader.loadTestsFromTestCase(TestLambdaHandler))
    suite.addTests(loader.loadTestsFromTestCase(TestWaitForReport))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)