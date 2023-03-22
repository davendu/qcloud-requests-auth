import hmac
import hashlib
import datetime

try:
    # python 2
    from urllib import quote
    from urlparse import urlparse
except ImportError:
    # python 3
    from urllib.parse import quote, urlparse

import requests


def sign(key, msg):
    """
    Modified from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, serviceName):
    """
    Modified from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    kDate = sign(('TC3' + key).encode('utf-8'), dateStamp)
    kService = sign(kDate, serviceName)
    kSigning = sign(kService, 'tc3_request')
    return kSigning


class QCloudRequestsAuth(requests.auth.AuthBase):
    """
    Auth class that allows us to connect to QCloud services
    """

    def __init__(self,
                 qcloud_secret_id,
                 qcloud_secret_key,
                 qcloud_host,
                 qcloud_region,
                 qcloud_service,
                 qcloud_action,
                 qcloud_apiversion):
        """
        Example usage for talking to an AWS Elasticsearch Service:

        AWSRequestsAuth(aws_access_key='YOURKEY',
                        aws_secret_access_key='YOURSECRET',
                        aws_host='search-service-foobar.us-east-1.es.amazonaws.com',
                        aws_region='us-east-1',
                        aws_service='es')

        """
        self.qcloud_secret_id = qcloud_secret_id
        self.qcloud_secret_key = qcloud_secret_key
        self.qcloud_host = qcloud_host
        self.qcloud_region = qcloud_region
        self.qcloud_service = qcloud_service
        self.qcloud_action = qcloud_action
        self.qcloud_apiversion = qcloud_apiversion

    def __call__(self, r):
        """
        Adds the authorization headers required by QCloud Signature v3.
        """
        aws_headers = self.get_qcloud_request_headers_handler(r)
        r.headers.update(aws_headers)
        return r

    def get_qcloud_request_headers_handler(self, r):
        """
        Override get_qcloud_request_headers_handler() if you have a
        subclass that needs to call get_qcloud_request_headers() with
        an arbitrary set of QCloud credentials. The default implementation
        calls get_qcloud_request_headers() with self.qcloud_access_key,
        and self.qcloud_secret_access_key
        """
        return self.get_qcloud_request_headers(r=r,
                                            qcloud_secret_id=self.qcloud_secret_id,
                                            qcloud_secret_key=self.qcloud_secret_key)

    def get_qcloud_request_headers(self, r, qcloud_secret_id, qcloud_secret_key):
        """
        Returns a dictionary containing the necessary headers for Amazon's
        signature version 4 signing process. An example return value might
        look like

            {
                'Authorization': '...',
                '...',
            }
        """
        # Create a date for headers and the credential string
        t = datetime.datetime.now()
        tUTC = datetime.datetime.utcnow()
        amzdate = str(int(t.timestamp()))
        datestamp = tUTC.strftime('%Y-%m-%d')  # Date w/o time for credential_scope

        canonical_uri = QCloudRequestsAuth.get_canonical_path(r)

        canonical_querystring = QCloudRequestsAuth.get_canonical_querystring(r)

        # Create the canonical headers and signed headers. Header names
        # and value must be trimmed and lowercase, and sorted in ASCII order.
        # Note that there is a trailing \n.
        canonical_headers = ('content-type:' + r.headers['content-type'] + '\n' +
                             'host:' + self.qcloud_host + '\n')

        # Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        signed_headers = 'content-type;host'

        # Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ('').
        body = r.body if r.body else bytes()
        try:
            body = body.encode('utf-8')
        except (AttributeError, UnicodeDecodeError):
            # On py2, if unicode characters in present in `body`,
            # encode() throws UnicodeDecodeError, but we can safely
            # pass unencoded `body` to execute hexdigest().
            #
            # For py3, encode() will execute successfully regardless
            # of the presence of unicode data
            body = body

        payload_hash = hashlib.sha256(body).hexdigest()

        # Combine elements to create create canonical request
        canonical_request = (r.method + '\n' + canonical_uri + '\n' +
                             canonical_querystring + '\n' + canonical_headers +
                             '\n' + signed_headers + '\n' + payload_hash)

        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = 'TC3-HMAC-SHA256'
        credential_scope = (datestamp + '/' + self.qcloud_service + '/' + 'tc3_request')
        string_to_sign = (algorithm + '\n' + amzdate + '\n' + credential_scope +
                          '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

        # Create the signing key using the function defined above.
        signing_key = getSignatureKey(qcloud_secret_key,
                                      datestamp,
                                      self.qcloud_service)

        # Sign the string_to_sign using the signing_key
        string_to_sign_utf8 = string_to_sign.encode('utf-8')

        signature = hmac.new(signing_key,
                             string_to_sign_utf8,
                             hashlib.sha256).hexdigest()

        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        authorization_header = (algorithm + ' ' + 'Credential=' + qcloud_secret_id +
                                '/' + credential_scope + ', ' + 'SignedHeaders=' +
                                signed_headers + ', ' + 'Signature=' + signature)

        headers = {
            'Authorization': authorization_header,
            'x-tc-timestamp': amzdate,
            'x-tc-action': self.qcloud_action,
            'x-tc-region': self.qcloud_region,
            'x-tc-version': self.qcloud_apiversion,
        }
        return headers

    @classmethod
    def get_canonical_path(cls, r):
        return "/"

    @classmethod
    def get_canonical_querystring(cls, r):
        """
        Create the canonical query string. According to AWS, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.

        This method assumes that the query params in `r` are *already*
        url encoded.  If they are not url encoded by the time they make
        it to this function, AWS may complain that the signature for your
        request is incorrect.

        It appears elasticsearc-py url encodes query paramaters on its own:
            https://github.com/elastic/elasticsearch-py/blob/5dfd6985e5d32ea353d2b37d01c2521b2089ac2b/elasticsearch/connection/http_requests.py#L64

        If you are using a different client than elasticsearch-py, it
        will be your responsibility to urleconde your query params before
        this method is called.
        """
        canonical_querystring = ''

        parsedurl = urlparse(r.url)
        querystring_sorted = '&'.join(sorted(parsedurl.query.split('&')))

        for query_param in querystring_sorted.split('&'):
            key_val_split = query_param.split('=', 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = ''

            if key:
                if canonical_querystring:
                    canonical_querystring += "&"
                canonical_querystring += u'='.join([key, val])

        return canonical_querystring
