#!/bin/bash
ARN=$1
OUTPUT_DIR=$2
mkdir -p $OUTPUT_DIR
JSON_OUTPUT="$(aws sts assume-role --role-arn $ARN --role-session-name rootshell_scan)"
ACCESS_KEY_ID=$(echo "$JSON_OUTPUT" | jq --raw-output .Credentials.AccessKeyId)
SECRET_ACCESS_KEY=$(echo "$JSON_OUTPUT" | jq --raw-output .Credentials.SecretAccessKey)
SESSION_TOKEN=$(echo "$JSON_OUTPUT" | jq --raw-output .Credentials.SessionToken)
echo -e "Access key: $ACCESS_KEY_ID\nSecret Access Key: $SECRET_ACCESS_KEY\nSession token: $SESSION_TOKEN"
echo "Launching scan for $ARN..."

./prowler_run.sh $ACCESS_KEY_ID $SECRET_ACCESS_KEY $SESSION_TOKEN $OUTPUT_DIR
