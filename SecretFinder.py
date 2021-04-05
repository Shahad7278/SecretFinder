#!/usr/bin/env python 
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based to LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k


import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse 
import jsbeautifier 
import webbrowser
import subprocess 
import base64
import requests 
import string 
import random 
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex 
_regex = {

     'AWS_Client_Secret.bb'       : r'(SecretAccessKey|aws_secret_access_key)',
     'AWS_Creds_File.bb'         : r'(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?\u003d.[0-9a-zA-Z\\/+]{20,40}',
     'AWS_EC2_Url.bb'     : r'ec2-[0-9-]+.cd-[a-z0-9-]+.compute.amazonaws.com"',
     'AWS_Access_Key_ID.bb'   : r'(AKIA[a-zA-Z0-9]{16})", "true,Or,(AccessKeyId|aws_access_key_id)", "true,Or,^(AKIA[a-zA-Z0-9]{16})", "true,Or,^((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})", "true,Or,[^a-zA-Z0-9]((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})',


     'RSA_PRIVATE_KEY'   : r'-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}',
     'SSH_EC_PRIVATE_KEY'     : r'-{5}BEGIN\sEC\sPRIVATE\sKEY-{5}',
     'aws_access_key_id '     : r'AKIA[0-9A-Z]{16}',
'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",

    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'PGP_PRIVATE_KEY'     : r'-{5}BEGIN\sPGP\sPRIVATE\sKEY-{5}',
    'mailchimp_key'         : r'[0-9a-f]{32}-us[0-9]{1,2}',
    'mailgun_key'    : r'key-[0-9a-zA-Z]{32}',
    'password_url'    : r'[a-z-0-9]{,8}:\/{2}[a-z-0-9]{,16}\:[a-z-0-9-!@#$%^&*()_+\,.<>?]{,16}@[a-z]{,64}\.[a-z]{,8}',
    'access_token '    : r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
    'picatic_api_key'     : r'sk_live_[0-9a-z]{32}',
    'restricted_stripe_api_keys'     : r'rk_live_[0-9a-zA-Z]{24}',
    'aws_mws_auth_token'       : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'ipv4'          : r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}',
    'ipv6'          : r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
    'md5'           : r'[a-f0-9]{32}',
    'cloudinary-basic-auth'     : r'cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
    'aws-client-id'       : r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    'aws-mws-key'           : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'mailchamp-api'    : r'[0-9a-f]{32}-us[0-9]{1,2}',
    'artifactory-password'    : r'(?: |=|:|\"|^)AP[0-9ABCDEF][a-zA-Z0-9]{8,}',
    'artifactory-token'       : r'(?: |=|:|\"|^)AKC[a-zA-Z0-9]{10,}',
    'auth-bearer'        : r'bearer [a-zA-Z0-9_\\-\\.=]+',
    'auth-http'        : r'(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'access_key'     : r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'base32'         : r'(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?',
    'base64'        : r'(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}',
    'mailto'        : r'(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+',
    'google-drive-key' : r'AIza[0-9A-Za-z\\-_]{35}',
    'google-oauth'   : r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
    'google-ouath-token'   : r'ya29\.[0-9A-Za-z\-_]+',
    'GCP_service_account'     : r'\"type\": \"service_account\"',
    'google-youtube-key'   : r'AIza[0-9A-Za-z\\-_]{35}',
    'heroku-api'    : r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'Authorization_Bearer.bb'     : r'bearer\\s*[a-zA-Z0-9_\\-\\.\u003d:_\\+\\/]+',
    'Youtube_Channel_ID.bb'    : r'https?:\\/\\/(www\\.)?youtube.com\\/channel\\/UC([-_a-z0-9]{22})',
    'Artifactory_API_Token.bb'     : r'(?:\\s|\u003d|:|\"|^)AKC[a-zA-Z0-9]{10,}',
    'slack_token'    : r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    'slack_webhook_url'  : r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"\

r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"\

r"[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com"\


r"(\\+[0-9]{2}|^\\+[0-9]{2}\\(0\\)|^\\(\\+[0-9]{2}\\)\\(0\\)|^00[0-9]{2}|^0)([0-9]{9}$|[0-9\\-\\s]{10}$)"\


r"[0-9a-f]{32}-us[0-9]{1,2}"\
r"[0-9a-f]{32}-us[0-9]{1,2}"\
r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"\
r"[0-9a-fA-F]{7}.[0-9a-fA-F]{32}"\
r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"\
r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"\
r"[0-9a-zA-Z/+]{40}"\
r"[0-9a-zA-Z_][5,31]"\
r"0-9]+-[0-9a-zA-Z]{40}"\
r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"\
r"((4\\d{3})|(5[1-5]\\d{2})|(6011))-?\\d{4}-?\\d{4}-?\\d{4}|3[4,7]\\d{13}"\

r"55[0-9a-fA-F]{32}"\
r"-{5}BEGIN\sEC\sPRIVATE\sKEY-{5}"\
r"-{5}BEGIN\sPGP\sPRIVATE\sKEY-{5}"\
r"-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5"\
r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$"\
r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"\
r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"\
r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"\

r"AAAA[a-zA-Z0-9_-]{5,100}:[a-zA-Z0-9_-]{140}"\
r"AAAA[A-Za-z0-9_-]{5,100}:[A-Za-z0-9_-]{140}"\
r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"\
r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}"\

r"AC[a-zA-Z0-9_\-]{32}"\
r"access[_-]?key[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"access[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"accessKey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"access[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"\
r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"\
r"access_token,production$[0-9a-z]{161[0-9a,]{32}"\
r"access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"access[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"accessToken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"account[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"account[_-]sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"accountsid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"admin[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"admin[_-]pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"admin[_-]user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"adzerk[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[a-f0-9]{32}"\
r"AIza[0-9A-Za-z-_]{35}"\
r"AIza[0-9A-Za-z-_]{35}"\
r"AIza[0-9A-Za-z\\-_]{35}"\
r"AKIA[0-9A-Z]{16}"\
r"(AKIA[a-zA-Z0-9]{16})"\

r"true,Or,(AccessKeyId|aws_access_key_id)"\


r"true,Or,^(AKIA[a-zA-Z0-9]{16})"\

r"true,Or,^((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"\

r"true,Or,[^a-zA-Z0-9]((A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"\
r"algolia[_-]?admin[_-]?key[_-]?1(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?admin[_-]?key[_-]?2(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?admin[_-]?key[_-]?mcm(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?api[_-]?key[_-]?mcm(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?api[_-]?key[_-]?search(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?search[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?search[_-]?key[_-]?1(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"algolia[_-]?search[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"alias[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"alicloud[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"alicloud[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"amazon[_-]?bucket[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"amazon[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\
r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"\
r"amzn.mws]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}"\
r"anaconda[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"android[_-]?docs[_-]?deploy[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ansible[_-]?vault[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aos[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aos[_-]?sec(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"AP[a-zA-Z0-9_\-]{32}"\
r"apiary[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"apigw[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[key|_key|\\s+]+[a-zA-Z0-9_\\-]{5,100}"\
r"api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}"\
r"api[key|_key|\s+]+[a-zA-Z0-9_\-]{7,100}"\
r"api[_-]?key[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[_-]?key[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"api[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\""\
r"app[_-]?bucket[_-]?perm(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"appclientsecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"apple[_-]?id[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"application[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]?report[_-]?token[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]?secrete(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"app[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"argos[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifactory[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifacts[_-]?aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifacts[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifacts[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"artifacts[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"assistant[_-]?iam[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"auth0[_-]?api[_-]?clientsecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"auth0[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"author[_-]?email[_-]?addr(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"author[_-]?npm[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"authsecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(aws_access|aws_secret|api[_-]?key|ListBucketResult|S3_ACCESS_KEY|Authorization:|RSA"\
r"PRIVATE|Index"\
r"of|aws_|secret|ssh-rsa"\
r"aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]access[_-]key[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"awsaccesskeyid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?access(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]access(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"awscn[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"awscn[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?config[_-]?accesskeyid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?config[_-]?secretaccesskey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]config(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]default[_-]region(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]secret[_-]access[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]secret[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"awssecretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?secrets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]secret[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?ses[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]?ses[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"aws[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[a-z-0-9]{,8}:\/{2}[a-z-0-9]{,16}\:[a-z-0-9-!@#$%^&*()_+\,.<>?]{,16}@[a-z]{,64}\.[a-z]{,8}"\
r"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}"\
r"(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?"\
r"[A-Za-z0-9]{125}"\
r"[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}"\
r"[A-Za-z0-9_]{255}"\
r"(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-zA-Z]+"\
r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*"\
r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*"\
r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"\
r"[a-zA-Z0-9-\\.\_]+\\.s3\\.amazonaws\\.com"\
r"a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"\
r"b2[_-]?app[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"b2[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[a-zA-Z0-9=:_\+\/-]{5,100}"\
r"bintray[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bintray[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bintray[_-]?gpg[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bintray[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bintraykey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bintray[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?pass[_-]?prod(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?pwd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bluemix[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"brackets[_-]?repo[_-]?oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"browser[_-]?stack[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"browserstack[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bucket[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"built[_-]?branch[_-]?deploy[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bundlesize[_-]?github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bx[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"bx[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cache[_-]?s3[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cargo[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cattle[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cattle[_-]?agent[_-]?instance[_-]?auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cattle[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"censys[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"certificate[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cf[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cheverny[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"chrome[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"chrome[_-]?refresh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ci[_-]?deploy[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ci[_-]?project[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ci[_-]?registry[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ci[_-]?server[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ci[_-]?user[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"claimr[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"claimr[_-]?db(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"claimr[_-]?superuser(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"claimr[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cli[_-]?e2e[_-]?cma[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"client[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"clojars[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?archived[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?audited[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?instance(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?order[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?parsed[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?processed[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudant[_-]?service[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloud[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudflare[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudflare[_-]?auth[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudflare[_-]?auth[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudflare[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+"\
r"cloudinary[_-]api[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudinary[_-]api[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudinary[_-]name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudinary[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cloudinary[_-]?url[_-]?staging(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"clu[_-]?repo[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"clu[_-]?ssh[_-]?private[_-]?key[_-]?base64(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cn[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cn[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cocoapods[_-]?trunk[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cocoapods[_-]?trunk[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"codacy[_-]?project[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"codeclimate[_-]?repo[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"codecov[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"coding[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"conekta[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"connectionstring(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"consumer[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"consumerkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"consumer[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?cma[_-]?test[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?integration[_-]?management[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?management[_-]?api[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?php[_-]?management[_-]?test[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?test[_-]?org[_-]?cma[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"contentful[_-]?v2[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"conversation[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"conversation[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cos[_-]?secrets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"coveralls[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"coveralls[_-]?repo[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"coveralls[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"coverity[_-]?scan[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"cypress[_-]?record[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"danger[_-]?github[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]dialect(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]logging(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]schema(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]schema[_-]test(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"database[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"datadog[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"datadog[_-]?app[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?connection(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]connection(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]dialect(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dbpasswd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dbpassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?pw(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]server(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"db[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dbuser(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ddgc[_-]?github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ddg[_-]?test[_-]?email[_-]?pw(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ddg[_-]?test[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"deploy[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"deploy[_-]?secure(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"deploy[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"deploy[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dgpg[_-]?passphrase(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"digitalocean[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"digitalocean[_-]?ssh[_-]?key[_-]?body(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"digitalocean[_-]?ssh[_-]?key[_-]?ids(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"django[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?hub[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dockerhub[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dockerhubpassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?passwd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?postgres[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"docker[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"doordash[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dropbox[_-]?oauth[_-]?bearer(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"droplet[_-]?travis[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dsonar[_-]?login(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"dsonar[_-]?projectkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"EAACEdEose0cBA[0-9A-Za-z]+"\
r"EAACEdEose0cBA[0-9A-Za-z]+"\
r"EAACEdEose0cBA[0-9A-Za-z]+"\
r"ec2-[0-9-]+.cd-[a-z0-9-]+.compute.amazonaws.com"\
r"elastic[_-]?cloud[_-]?auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"elastic[_-]host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"elastic[_-]port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"elastic[_-]prefix(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"elasticsearch[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"email[_-]host[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"encryption[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"end[_-]?user[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?github[_-]?oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?heroku[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"env[_-]?sonatype[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"eureka[_-]?awssecretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"exp[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*'"\
r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$"\
r"(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}"\
r"facebook[_-]app[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"facebook[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"fb[_-]app[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"fb[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"fb[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"\
r"file[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firebase[_-]?api[_-]?json(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firebase[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firebase[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firebase[_-]?project[_-]?develop(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firebase[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"firefox[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"flask[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"flickr[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"flickr[_-]?api[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"fossa[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(ftp|ftps|http|https)://[A-Za-z0-9-_:\.~]+(@)"\
r"(ftp|ftps|http|https)://[A-Za-z0-9-_:\\.~]+(@)"\
r"ftp[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ftp[_-]?login(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ftp[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ftp[_-]?pw(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ftp[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ftp[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]base[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]client[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]client[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]protocol(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gatsby[_-]wordpress[_-]user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gcloud[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gcloud[_-]?project(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gcloud[_-]?service[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gcr[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gcs[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ghb[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?next[_-]?oauth[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?oauth[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ghost[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?repo[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?author[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?author[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?committer[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?committer[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?deployment[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?hunter[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?hunter[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?oauth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?pwd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?release[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?repo(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?tokens(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gitlab[_-]?user[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"git[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gogs[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?account[_-]?type(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?client[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?client[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?maps[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]oauth[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]?private[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"google[_-]server[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?key[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?keyname(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?ownertrust(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?passphrase(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?private[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gpg[_-]?secret[_-]?keys(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gradle[_-]?publish[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gradle[_-]?publish[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gradle[_-]?signing[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gradle[_-]?signing[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gren[_-]?github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"grgit[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"gsecr(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"hab[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"hab[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"hb[_-]?codesign[_-]?gpg[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"hb[_-]?codesign[_-]?key[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"\
r"heroku[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?oauth[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?secret[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"heroku[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"\
r"hockeyapp[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"homebrew[_-]?github[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"htaccess[_-]pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"htaccess[_-]user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"\
r"https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}"\
r"https?:\\/\\/(www\\.)?youtube.com\\/channel\\/UC([-_a-z0-9]{22})"\
r"hub[_-]?dxia2[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?\u003d.[0-9a-zA-Z\\/+]{20,40}"\
r"ij[_-]?repo[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ij[_-]?repo[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"incident[_-]bot[_-]name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"incident[_-]channel[_-]name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"index[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"integration[_-]?test[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"integration[_-]?test[_-]?appid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"internal[_-]?secrets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ios[_-]?docs[_-]?deploy[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"itest[_-]?gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jdbc[_-]?databaseurl(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jdbc[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jdbc:mysql(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]passphrase(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]public[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]secret[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]secret[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"jwt[_-]user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kafka[_-]?admin[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kafka[_-]?instance[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kafka[_-]?rest[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"key-[0-9a-zA-Z]{32}"\
r"key-[0-9a-zA-Z]{32}"\
r"(key|KEY)(:|=)[0-9A-Za-z\\-]{10}"\
r"keyPassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"keystore[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kovan[_-]?private[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kubecfg[_-]?s3[_-]?path(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kubeconfig(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"kxoltsn3vogdop92m(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"leanplum[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lektor[_-]?deploy[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lektor[_-]?deploy[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lighthouse[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"linkedin[_-]?client[_-]?secretor"\
r"lottie[_-]?s3[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"linux[_-]?signing[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ll[_-]?publish[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ll[_-]?shared[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"looker[_-]?test[_-]?runner[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lottie[_-]?happo[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lottie[_-]?happo[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lottie[_-]?s3[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lottie[_-]?upload[_-]?cert[_-]?key[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"magento[_-]?auth[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"magento[_-]?auth[_-]?username"\
r"(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"magento[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailchimp[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailchimp[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]driver(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]?encryption(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]encryption(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailer[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]from[_-]address(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]from[_-]name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?priv[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?pub[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?pub[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]?secret[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mailgun[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]?port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+"\
r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]{10}"\
r"mail[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mail[_-]username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"manage[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"managementapiaccesstoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"management[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"manage[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mandrill[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"manifest[_-]?app[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"manifest[_-]?app[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mapbox[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mapboxaccesstoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mapbox[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mapbox[_-]?aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"maps[_-]api[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mg[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mg[_-]?public[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mh[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mh[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mile[_-]?zero[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"minio[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"minio[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mix[_-]pusher[_-]app[_-]cluster(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mix[_-]pusher[_-]app[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"multi[_-]?bob[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"multi[_-]?connect[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"multi[_-]?disconnect[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"multi[_-]?workflow[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"multi[_-]?workspace[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"my[_-]?secret[_-]?env(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?hostname(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysqlmasteruser(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?root[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysqlsecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"mysql[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nativeevents(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"netlify[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"new[_-]?relic[_-]?beta[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nexus[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nexuspassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ngrok[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ngrok[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"node[_-]?env(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"node[_-]?pre[_-]?gyp[_-]?accesskeyid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"node[_-]?pre[_-]?gyp[_-]?github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"node[_-]?pre[_-]?gyp[_-]?secretaccesskey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"non[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"now[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"npm[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nuget[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nuget[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"nuget[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"numbers[_-]?service[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth2[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth[_-]discord[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth[_-]discord[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oauth[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"object[_-]?storage[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"object[_-]?storage[_-]?region[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"object[_-]?store[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"object[_-]?store[_-]?creds(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"oc[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"octest[_-]?app[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"octest[_-]?app[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"octest[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ofta[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ofta[_-]?region(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ofta[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"okta[_-]?client[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"okta[_-]?oauth2[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"okta[_-]?oauth2[_-]?clientsecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"omise[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"omise[_-]?pkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"omise[_-]?pubkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"omise[_-]?skey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"onesignal[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"onesignal[_-]?user[_-]?auth[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"open[_-]?whisk[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"openwhisk[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"os[_-]?auth[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"os[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ossrh[_-]?jira[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ossrh[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ossrh[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ossrh[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ossrh[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"packagecloud[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pagerduty[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"parse[_-]?js[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"passwd\s*[`=:\"]+\s*[^\s]+)"\
r"password"\
r"is\s*[`=:\"]*\s*[^\s]+|"\
r"(password|pwd|passwd)(\\s*=\\s*|\\s*:\\s*|\\s*is\\s*)(^!0,)(^image:!0)[\\w\\W][^\n]{0,10}"\
r"password\s*[`=:\"]+\s*[^\s]+|"\
r"passwordtravis(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"paypal[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"paypal[_-]identity[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"paypal[_-]sandbox(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"paypal[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"paypal[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"percy[_-]?project(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"percy[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"personal[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"personal[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pg[_-]?database(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pg[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"places[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"places[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"playbooks[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"plotly[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"plugin[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"postgres[_-]?env[_-]?postgres[_-]?db(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"postgres[_-]?env[_-]?postgres[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"postgres[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"postgresql[_-]?db(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"postgresql[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"prebuild[_-]?auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"preferred[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pring[_-]?mail[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"private[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"private[_-]?signing[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"prod[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"prod[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"prod[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"project[_-]?config(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"publish[_-]?access(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"publish[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"publish[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pusher[_-]app[_-]cluster(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pusher[_-]app[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pusher[_-]app[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pusher[_-]app[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pushover[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"pwd\s*[`=:\"]*\s*[^\s]+|"\
r"pypi[_-]?passowrd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"qiita[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"queue[_-]driver(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"quip[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"R_[0-9a-f]{32}"\
r"R_[0-9a-f]{32}"\
r"rabbitmq[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"randrmusicapiaccesstoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rediscloud[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"redis[_-]host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"redis[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"redis[_-]port(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"redis[_-]?stunnel[_-]?urls(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"refresh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"registry[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"registry[_-]?secure(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"release[_-]?gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"release[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"reporting[_-]?webdav[_-]?pwd(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"reporting[_-]?webdav[_-]?url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"repotoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"response[_-]auth[_-]jwt[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"response[_-]data[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rest[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rinkeby[_-]?private[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rk_live_[0-9a-zA-Z]{24}"\
r"root[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ropsten[_-]?private[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"route53[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(?:r|s)k_live_[0-9a-zA-Z]{24}"\
r"rsq0csp-[0-9A-Za-z\\-\\_]{43}"\
r"rtd[_-]?key[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rtd[_-]?store[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"rubygems[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"\
r"s3.amazonaws.com/[a-zA-Z0-9-\.\_]"\
r"s3.amazonaws.com/[a-zA-Z0-9-\\.\_]+"\
r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com"\
r"s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com"\
r"|s3-[a-zA-Z0-9-\.\_\/]+"\
r"|s3://[a-zA-Z0-9-\.\_]+"\
r"s3-[a-zA-Z0-9-\.\_\/]"\
r"s3-[a-zA-Z0-9-\\.\\_/]+"\
r"s3://[a-zA-Z0-9-\.\_]+"\
r"s3://[a-zA-Z0-9-\\.\_]+"\
r"s3[_-]?bucket[_-]?name[_-]?app[_-]?logs(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?bucket[_-]?name[_-]?assets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\\._]+)"\
r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)"\
r"s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?key[_-]?app[_-]?logs(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?key[_-]?assets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?secret[_-]?app[_-]?logs(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?secret[_-]?assets(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"s3[_-]?user[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sacloud[_-]?access[_-]?token[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sacloud[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sacloud[_-]?api(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"salesforce[_-]?bulk[_-]?test[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sandbox[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sandbox[_-]?aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sa[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sauce[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"scrutinizer[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sdr[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?0(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?10(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?11(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?1(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?2(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?3(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?4(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?5(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?6(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?7(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?8(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?9(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(SecretAccessKey|aws_secret_access_key)"\
r"secretaccesskey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret[_-]?key[_-]?base(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"security[_-]credentials(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"segment[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"selion[_-]?log[_-]?level[_-]?dev(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"selion[_-]?selenium[_-]?host(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid[_-]?username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendgrid[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"send[_-]keys(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sendwithus[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sentry[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sentry[_-]?default[_-]?org(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sentry[_-]dsn(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sentry[_-]?endpoint(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sentry[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"service[_-]?account[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ses[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ses[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"session[_-]driver(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"session[_-]lifetime(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"setdstaccesskey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"setdstsecretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"setsecretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sf[_-]username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sid[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sid[_-]twilio(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"signing[_-]?key[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"signing[_-]?key[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"signing[_-]?key[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"signing[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"SK[0-9a-fA-F]{32}"\
r"sk_live_[0-9a-z]{32}"\
r"sk_live_[0-9a-z]{32}"\
r"sk_live_(0-9a-zA-Z]{24}"\
r"sk_live_[0-9a-zA-Z]{24}"\
r"slack[_-]channel(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]incoming[_-]webhook(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]outgoing[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]signing[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]webhook(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slack[_-]webhook[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slash[_-]?developer[_-]?space[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slash[_-]?developer[_-]?space(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"slate[_-]?user[_-]?email(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"snoowrap[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"snoowrap[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"snoowrap[_-]?refresh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"snyk[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"snyk[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"socrata[_-]?app[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"socrata[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonar[_-]?organization[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonar[_-]?project[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonar[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?gpg[_-]?key[_-]?name(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?gpg[_-]?passphrase(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?nexus[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatypepassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?token[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sonatype[_-]?token[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"soundcloud[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"soundcloud[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"spaces[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"spaces[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"spotify[_-]?api[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"spotify[_-]?api[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"spring[_-]?mail[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sqOatp-[0-9A-Za-z-_]{22}"\
r"sqOatp-[0-9A-Za-z\\-_]{22}"\
r"sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}"\
r"sqOatp-[0-9A-Za-z\\-_]{22}|EAAA[a-zA-Z0-9]{60}"\
r"sqsaccesskey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sqssecretkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]access[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]app[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]appid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]app(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]?reader[_-]?sdk[_-]?repository[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"squareSecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"square[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"squareToken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"srcclr[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ssh2[_-]auth[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sshkey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"sshpass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"ssmtp[_-]?config(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"staging[_-]?base[_-]?url[_-]?runscope(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"starship[_-]?account[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"starship[_-]?auth[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"star[_-]?test[_-]?bucket(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"star[_-]?test[_-]?location(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"star[_-]?test[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"storePassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stormpath[_-]?api[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stormpath[_-]?api[_-]?key[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]?private(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]?public(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]publishable[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]secret[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripe[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]?publishable[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]?secret[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripSecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]secret[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"strip[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"stripToken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"(?:\\s|\u003d|:|\"|^)AKC[a-zA-Z0-9]{10,}"\
r"surge[_-]?login(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"surge[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"svn[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"\
r"tesco[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"tester[_-]?keys[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"test[_-]?github[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"test[_-]?test(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"thera[_-]?oss[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"token=[0-9A-Za-z\\-]{5,100}"\
r"TOKEN[\\-|_|A-Z0-9]*(\'|\")?(:|=)(\'|\")?[\\-|_|A-Z0-9]{10}"\
r"token[_-]?core[_-]?java(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"token[_-]twilio(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?access[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?api[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?branch(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?com[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?e2e[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?pull[_-]?request(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?secure[_-]?env[_-]?vars(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"travis[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"trex[_-]?client[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"trex[_-]?okta[_-]?client[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"trusted[_-]hosts(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}"\
r"twi[_-]auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]account[_-]id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]account[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]account[_-]sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]accountsid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]api[_-]auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilioapiauth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]api[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?api[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]api[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilioapisecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilioapisid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]api(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]api[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilioapitoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"TwilioAuthKey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"TwilioAuthSid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]auth(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]auth[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilioauthtoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?chat[_-]?account[_-]?api[_-]?service(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?configuration[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"TwilioKey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twiliosecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]secret[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"TwilioSID(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twilio[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twiliotoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twine[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twi[_-]sid(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter.*[1-9][0-9]+-[0-9a-zA-Z]{40}"\
r"twitter[_-]api[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]?consumer[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]consumer[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]?consumer[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]consumer[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitterKey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitteroauthaccesssecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitteroauthaccesstoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitterSecret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"twitter[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"unity[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"unity[_-]?serial(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"urban[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"urban[_-]?master[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"urban[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"user[_-]?assets[_-]?access[_-]?key[_-]?id(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"user[_-]?assets[_-]?secret[_-]?access[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"usertravis(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"use[_-]?ssh(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"vip[_-]?github[_-]?deploy[_-]?key[_-]?pass(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"vip[_-]?github[_-]?deploy[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"virustotal[_-]?apikey(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"visual[_-]?recognition[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"vscetoken(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"v[_-]?sfdc[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"v[_-]?sfdc[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wakatime[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"watson[_-]?conversation[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"watson[_-]?device[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"watson[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?basic[_-]?password[_-]?2(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?basic[_-]?password[_-]?3(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?basic[_-]?password[_-]?4(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?basic[_-]?password[_-]?5(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?basic[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?fb[_-]?password[_-]?2(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?fb[_-]?password[_-]?3(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?fb[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"widget[_-]?test[_-]?server(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wincert[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wordpress[_-]?db[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wordpress[_-]?db[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wordpress[_-]password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wporg[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?db[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?db[_-]?user(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?prepare[_-]?dir(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?report[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?ssh[_-]?connect(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\

r"www[_-]?googleapis[_-]?com(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"xoxb-[0-9A-Za-z\\-]{50}"\
r"xoxb-[0-9A-Za-z\\-]{51}"\
r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"\
r"xox[baprs]-([0-9a-zA-Z]{10,48})"\
r"xoxp-[0-9A-Za-z\\-]{71}"\
r"xoxp-[0-9A-Za-z\\-]{72}"\
r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"\
r"ya29\.[0-9A-Za-z\-_]+"\
r"ya29\\.[0-9A-Za-z\\-\_]+"\
r"ya29\\.[0-9A-Za-z\\-_]+"\
r"yangshun[_-]?gh[_-]?password(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yangshun[_-]?gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?account[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?account[_-]?refresh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?partner[_-]?client[_-]?secret(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?partner[_-]?refresh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"yt[_-]?server[_-]?api[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]api[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]password"\
r"zendesk[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]?travis[_-]?github(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]url(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zendesk[_-]username(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zen[_-]key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zensonatypepassword(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zen[_-]tkn(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zen[_-]token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zhuliang[_-]?gh[_-]?token(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
r"zopim[_-]?account[_-]?key(\\s*=\\s*|\\s*:\\s*)[\\w\\W][^\n]{0,10}"\
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
}

_template = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>LinkFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$
  
  <a class='button' contenteditable='false' href='https://github.com/m4ll0k/SecretFinder/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path></svg></span> Report an issue.</a>
</body>
</html>
'''

def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help'%sys.argv[0])
    print('Error: %s'%msg)
    sys.exit(0)

def getContext(matches,content,name,rex='.+?'):
    ''' get context '''
    items = []
    matches2 =  []
    for  i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s'%(rex,m,rex),content,re.IGNORECASE)

        item = {
            'matched'          : m,
            'name'             : name,
            'context'          : context,
            'multi_context'    : True if len(context) > 1 else False
        } 
        items.append(item)
    return items


def parser_file(content,mode=1,more_regex=None,no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";",";\r\n").replace(",",",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1],re.VERBOSE|re.I)
        if mode == 1:
            all_matches = [(m.group(0),m.start(0),m.end(0)) for m in re.finditer(r,content)]
            items = getContext(all_matches,content,regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched' : m.group(0),
                'context' : [],
                'name'    : regex[0],
                'multi_context' : False
            } for m in re.finditer(r,content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex,item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items
        

def parser_input(input):
    ''' Parser Input '''
    # method 1 - url 
    schemes = ('http://','https://','ftp://','file://','ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input,'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8','replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths)> 0 else parser_error('Input with wildcard does not match any files.'))
        
    # method 5 - local file 
    path = "file://%s"% os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error('file could not be found (maybe you forgot to add http/https).')]


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull,os.O_RDWR)
    try:
        text_file = open(args.output,"wb")
        text_file.write(_template.replace('$$content$$',output).encode('utf-8'))
        text_file.close()
        
        print('URL to access output: file://%s'%os.path.abspath(args.output))
        file = 'file:///%s'%(os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open',file])
        else:
            webbrowser.open(file) 
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s'%(args.output,err))
    finally:
        os.dup2(hide,1)

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name')+'\t->\t'+match.get('matched').encode('ascii','ignore').decode('utf-8'))

def urlParser(url):
    ''' urlParser ''' 
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc 
    urlParser.this_path = parse.scheme + '://' + parse.netloc  + '/' + parse.path

def extractjsurl(content,base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else [] 
        if src != []:
            if src.startswith(('http://','https://','ftp://','ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://'+src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src 
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src 
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src 
        ignore = []
        for i in args.ignore.split(';'):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp 
    if args.only:
        temp = all_src 
        only = []
        for i in args.only.split(';'):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only 
    return all_src

def send_request(url):
    ''' Send Request ''' 
    # read local file 
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://',FileAdapter())
        return s.get(url).content.decode('utf-8','replace')
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent'      : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept'          : 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language' : 'en-US,en;q=0.8',
        'Accept-Encoding' : 'gzip'
    }
    if args.headers:
        for i in args.header.split('\\n'):
            # replace space and split
            name,value = i.replace(' ','').split(':')
            headers[name] = value 
    # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)
    # proxy 
    proxies = {}
    if args.proxy:
        proxies.update({
            'http'  : args.proxy,
            'https' : args.proxy,
            # ftp 
        })
    try:
        resp = requests.get(
            url = url,
            verify = False,
            headers = headers, 
            proxies = proxies
        )
        return resp.content.decode('utf-8','replace')
    except Exception as err:
        print(err)
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e","--extract",help="Extract all javascript links located in a page and process it",action="store_true",default=False)
    parser.add_argument("-i","--input",help="Input a: URL, file or folder",required="True",action="store")
    parser.add_argument("-o","--output",help="Where to save the file, including file name. Default: output.html",action="store", default="output.html")
    parser.add_argument("-r","--regex",help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",action="store")
    parser.add_argument("-b","--burp",help="Support burp exported file",action="store_true")
    parser.add_argument("-c","--cookie",help="Add cookies for authenticated JS files",action="store",default="")
    parser.add_argument("-g","--ignore",help="Ignore js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-n","--only",help="Process js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-H","--headers",help="Set headers (\"Name:Value\\nName:Value\")",action="store",default="")
    parser.add_argument("-p","--proxy",help="Set proxy (host:port)",action="store",default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]
    
    mode = 1 
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(args.regex,''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10,50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()

        _regex.update({
            'custom_regex' : args.regex
        })

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content,args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = '' 
    for url in urls:
        print('[ + ] URL: '+url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get('js')
            url = url.get('url')
        
        matched = parser_file(file,mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>'%(escape(url),escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '<div class="text">%s'%(_named.replace('_',' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    # remove duplicate
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '</a><div class="container">%s</div></div>'%(context)
                            body = body.replace(
                                context,'<span style="background-color:yellow">%s</span>'%context)
                            no_dup.append(context)
                        # --
                else:
                    body += '</a><div class="container">%s</div></div>'%(match.get('context')[0] if len(match.get('context'))>1 else match.get('context'))
                    body = body.replace(
                        match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')),
                        '<span style="background-color:yellow">%s</span>'%(match.get('context') if len(match.get('context'))>1 else match.get('context'))
                    )
                output += header + body 
    if args.output != 'cli':
        html_save(output)
