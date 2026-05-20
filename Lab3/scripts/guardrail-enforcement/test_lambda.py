"""Unit tests for guardrail enforcement Lambda."""

import unittest
from unittest.mock import patch, MagicMock
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lambda_function import is_excluded_role, lambda_handler


class TestIsExcludedRole(unittest.TestCase):
    
    def test_excluded_prefix(self):
        self.assertTrue(is_excluded_role('AWSServiceRoleForConfig'))
        self.assertTrue(is_excluded_role('iam-guardrails-enforcement'))
        
    def test_excluded_suffix(self):
        self.assertTrue(is_excluded_role('my-breakglass-role'))
        
    def test_not_excluded(self):
        self.assertFalse(is_excluded_role('my-application-role'))
        self.assertFalse(is_excluded_role('developer-role'))


class TestLambdaHandler(unittest.TestCase):
    
    @patch.dict(os.environ, {
        'PERMISSION_BOUNDARY_ARN': 'arn:aws:iam::123456789012:policy/test-boundary',
        'ENABLE_REMEDIATION': 'true'
    })
    @patch('lambda_function.boto3.client')
    def test_create_role_event(self, mock_boto):
        mock_iam = MagicMock()
        mock_boto.return_value = mock_iam
        
        mock_iam.get_role.return_value = {
            'Role': {'RoleName': 'test-role'}
        }
        
        event = {
            'detail': {
                'eventName': 'CreateRole',
                'requestParameters': {
                    'roleName': 'test-role'
                }
            }
        }
        
        response = lambda_handler(event, None)
        
        self.assertEqual(response['statusCode'], 200)
        self.assertEqual(len(response['body']['results']), 1)


if __name__ == '__main__':
    unittest.main()