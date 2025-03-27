#!/bin/bash
# Pass the arn of a role you want to assume and the name of the profile it should map to, this will add it to your aws credentials automatically
export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s" \
  $(aws sts assume-role \
    --role-arn $1 \
    --role-session-name MySessionName \
    --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" \
    --output text))

echo >>~/.aws/credentials
echo "[$2]" >>~/.aws/credentials
echo "aws_access_key_id = $AWS_ACCESS_KEY_ID" >>~/.aws/credentials
echo "aws_secret_access_key = $AWS_SECRET_ACCESS_KEY" >>~/.aws/credentials
echo "aws_session_token = $AWS_SESSION_TOKEN" >>~/.aws/credentials
