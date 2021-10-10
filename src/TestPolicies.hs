{-# LANGUAGE OverloadedStrings #-}
module TestPolicies where

import Data.ByteString

testJSONCondition :: ByteString
testJSONCondition = "{ \
  \ \"Version\": \"2012-10-17\", \
  \ \"Statement\": [ \
    \ { \
      \ \"Sid\": \"FirstStatement\", \
      \ \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:user/testX\"}, \
      \ \"Effect\": \"Allow\", \
      \ \"Action\":  \"iam:ChangePassword \" , \
      \ \"Resource\": \"*\" , \
      \ \"Condition\": {\"StringEquals\":{\"aws:username\":\"b\"}} \
    \ }] \
  \ }"

testJSONPutObject :: ByteString
testJSONPutObject = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:user/testX\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::test2\"] \
\    }, \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"NotPrincipal\": {\"AWS\": \"arn:aws:iam::123456789012:user/test3\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::test3\"] \
\    }, \
\    { \
\      \"Sid\": \"Stmt1617054490055\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:user/test1\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Deny\", \
\      \"NotResource\": \"arn:aws:s3:::test2*\" \
\    } \
\  ] \
\}"

testCloudWatch :: ByteString
testCloudWatch = "{ \ 
\     \"Version\": \"2012-10-17\", \
\     \"Statement\": [ \
\         { \
\             \"Sid\": \"foo\", \
\             \"Principal\": { \"AWS\": \"arn:aws:iam::123456789012:role/testrole\" }, \
\             \"Effect\": \"Allow\", \
\             \"Action\": [ \
\                 \"logs:PutLogEvents\", \
\                 \"logs:CreateLogStream\", \
\                 \"logs:CreateLogGroup\" \
\             ], \
\             \"Resource\": [ \
\                 \"arn:aws:logs:eu-west-2:123456789012:log-group:/aws/lambda/test-lambda:*:*\", \
\                 \"arn:aws:logs:eu-west-2:123456789012:log-group:/aws/lambda/test-lambda:*\" \
\             ] \
\         } \
\   ] \
\}"


allowAllS3InAccount :: ByteString
allowAllS3InAccount = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"123456789012\"}, \
\      \"Action\": \"*\", \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::*\"] \
\    } \
\  ] \
\}"

allowPutObjectToAWSUser :: ByteString
allowPutObjectToAWSUser = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:user/test1\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::test2\"] \
\    } \
\ ] \
\}"

allowPutObjectToAWSUserInAnotherAccount :: ByteString
allowPutObjectToAWSUserInAnotherAccount = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789013:user/test1\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::test2\"] \
\    } \
\ ] \
\}"

allowChangePasswordToAWSUser :: ByteString
allowChangePasswordToAWSUser = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:user/test1\"}, \
\      \"Action\": [ \
\        \"iam:ChangePassword\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": \"*\" \
\    } \
\ ] \
\}"

allowPutObjectToAWSUserByCondition :: ByteString
allowPutObjectToAWSUserByCondition = "{ \
\  \"Version\": \"2012-10-17\", \
\  \"Statement\": [ \
\    { \
\      \"Sid\": \"Stmt1617054271329\", \
\      \"Principal\": {\"AWS\": \"arn:aws:iam::123456789012:root\"}, \
\      \"Action\": [ \
\        \"s3:PutObject\" \
\      ], \
\      \"Effect\": \"Allow\", \
\      \"Resource\": [\"arn:aws:s3:::test2\"], \
\      \"Condition\": {\"StringEquals\":{\"aws:username\":\"test1\"}} \
\    } \
\ ] \
\}"
