import datetime
import hashlib
import mock
import requests
import sys
import unittest

from qcloud_requests_auth.qcloud_auth import QCloudRequestsAuth


class TestQCloudRequestsAuth(unittest.TestCase):
    """
    Tests for QCloudRequestsAuth
    """

    def test_no_query_params(self):
        """
        Assert we generate the 'correct' cannonical query string
        and canonical path for a request with no query params

        Correct is relative here b/c 'correct' simply means what
        the QCloud CVM service expects
        """
        url = 'http://cvm.tencentcloudapi.com:80/'
        mock_request = mock.Mock()
        mock_request.url = url
        self.assertEqual('/', QCloudRequestsAuth.get_canonical_path(mock_request))
        self.assertEqual('', QCloudRequestsAuth.get_canonical_querystring(mock_request))

    def test_characters_escaped_in_path(self):
        """
        Assert we generate the 'correct' cannonical query string
        and path a request with characters that need to be escaped
        """
        url = 'http://cvm.tencentcloudapi.com:80/+foo.*/_stats'
        mock_request = mock.Mock()
        mock_request.url = url
        self.assertEqual('/', QCloudRequestsAuth.get_canonical_path(mock_request))
        self.assertEqual('', QCloudRequestsAuth.get_canonical_querystring(mock_request))

    def test_path_with_querystring(self):
        """
        Assert we generate the 'correct' cannonical query string
        and path for request that includes a query stirng
        """
        url = 'http://cvm.tencentcloudapi.com:80/my_index/?pretty=True'
        mock_request = mock.Mock()
        mock_request.url = url
        self.assertEqual('/', QCloudRequestsAuth.get_canonical_path(mock_request))
        self.assertEqual('pretty=True', QCloudRequestsAuth.get_canonical_querystring(mock_request))

    def test_multiple_get_params(self):
        """
        Assert we generate the 'correct' cannonical query string
        for request that includes more than one query parameter
        """
        url = 'http://cvm.tencentcloudapi.com:80/index/type/_search?scroll=5m&search_type=scan'
        mock_request = mock.Mock()
        mock_request.url = url
        self.assertEqual('scroll=5m&search_type=scan', QCloudRequestsAuth.get_canonical_querystring(mock_request))

    def test_post_request_with_get_param(self):
        """
        Assert we generate the 'correct' cannonical query string
        for a post request that includes GET-parameters
        """
        url = 'http://cvm.tencentcloudapi.com:80/index/type/1/_update?version=1'
        mock_request = mock.Mock()
        mock_request.url = url
        mock_request.method = "POST"
        self.assertEqual('version=1', QCloudRequestsAuth.get_canonical_querystring(mock_request))

    def test_auth_for_get(self):
        auth = QCloudRequestsAuth(qcloud_secret_id='YOURKEY',
                               qcloud_secret_key='YOURSECRET',
                               qcloud_host='cvm.tencentcloudapi.com',
                               qcloud_region='ap-shanghai',
                               qcloud_service='cvm',
                               qcloud_action='DescribeInstances',
                               qcloud_apiversion='2017-03-12')
        url = 'http://cvm.tencentcloudapi.com:80/'
        mock_request = requests.Request(method="GET", url=url).prepare()


        frozen_datetime = datetime.datetime(2016, 6, 18, 22, 4, 5)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = frozen_datetime
            auth(mock_request)
        print(mock_request.headers)
        self.assertEqual({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'TC3-HMAC-SHA256 Credential=YOURKEY/2016-06-18/cvm/tc3_request'
                                ', SignedHeaders=content-type;host, '
                                'Signature=1827327c7138a0193e2883c6f865cffe94b5b4444818eda77324898cc73a37ad',
            "x-tc-timestamp": "1466258645",
            "x-tc-action": "DescribeInstances",
            "x-tc-region": "ap-shanghai",
            "x-tc-version": "2017-03-12",
        }, mock_request.headers)


    def test_auth_for_post_with_json_body(self):
        auth = QCloudRequestsAuth(qcloud_secret_id='YOURKEY',
                               qcloud_secret_key='YOURSECRET',
                               qcloud_host='cvm.tencentcloudapi.com',
                               qcloud_region='ap-shanghai',
                               qcloud_service='cvm',
                               qcloud_action='DescribeInstances',
                               qcloud_apiversion='2017-03-12')
        url = 'http://cvm.tencentcloudapi.com:80/'
        mock_request = requests.Request(method="POST", url=url, json={"Limit": 10}).prepare()

        frozen_datetime = datetime.datetime(2016, 6, 18, 22, 4, 5)
        with mock.patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = frozen_datetime
            auth(mock_request)
        self.assertEqual({
            'Content-Length': '13',
            'Content-Type': 'application/json',
            'Authorization': 'TC3-HMAC-SHA256 Credential=YOURKEY/2016-06-18/cvm/tc3_request'
                                ', SignedHeaders=content-type;host, '
                                'Signature=51ed57e4b544a988b76ebd522a9df26273c370c411be3bd83911a24312dfbae5',
            "x-tc-timestamp": "1466258645",
            "x-tc-action": "DescribeInstances",
            "x-tc-region": "ap-shanghai",
            "x-tc-version": "2017-03-12",
        }, mock_request.headers)


