# QCloud Signature Version 3 Signing Process with python requests

QCloud TC3-HMAC-SHA256 signature is basically a fork of AWSv4. This library can help you to call API directly
using Requests, so you can avoid the freaking other library, if you want.

## Use at client with `requests`

```python
import qcloud_auth
import requests

auth_plugin = qcloud_auth.QCloudRequestsAuth("AKID****************", 
                                             "****************",
                                             "cvm.tencentcloudapi.com",
                                             "ap-guangzhou",
                                             "cvm",
                                             "DescribeInstances",
                                             "2017-03-12"
                                             )
ret = requests.get("https://cvm.tencentcloudapi.com/", auth=auth_plugin)
```