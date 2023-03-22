from setuptools import setup


setup(
    name='qcloud-requests-auth',
    version='0.0.1',
    author='David Muller',
    author_email='davehmuller@gmail.com',
    packages=['qcloud_requests_auth'],
    url='https://github.com/davendu/qcloud-requests-auth',
    description=' Tencent cloud signature version 3 (TC3-HMAC-SHA256) signing process for the python requests module. Forked from  DavidMuller/aws-requests-auth',
    long_description='See https://github.com/davendu/qcloud-requests-auth for installation and usage instructions.',
    install_requires=['requests>=0.14.0'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ]
)
