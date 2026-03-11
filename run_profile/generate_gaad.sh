#!/bin/bash

if [ $# -eq 0 ]; then
  echo "Usage: $0 \"OUTPUT_FILE\""
  echo "Example: $0 $1"
  exit 1
fi

PROFILES="$(grep -oP '(?<=\[).*(?=\])' ~/.aws/credentials | grep -v default)"

if [ -z "$PROFILES" ]; then
  echo "No profiles found in ~/.aws/credentials"
  exit 1
fi

echo "Running aws iam get-account-authorization-details on all profiles..."
echo "-------------------"

for profile in $PROFILES; do
  echo "PROFILE: $profile"
  aws --profile "$profile" iam get-account-authorization-details >>$1
  echo "OUTPUTTED GAAD for $profile"
  echo "-------------------"
done
