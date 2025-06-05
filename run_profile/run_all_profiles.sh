#!/bin/bash
# TODO: Alias the aws command instead? might work better and allow it to be combined with other tools...

if [ $# -eq 0 ]; then
  echo "Usage: $0 \"AWS_COMMAND\""
  echo "Example: $0 s3 ls"
  exit 1
fi

PROFILES="$(grep -oP '(?<=\[).*(?=\])' ~/.aws/credentials | grep -v default)"

if [ -z "$PROFILES" ]; then
  echo "No profiles found in ~/.aws/credentials"
  exit 1
fi

echo "Running aws $* on all profiles..."
echo "-------------------"

for profile in $PROFILES; do
  echo "PROFILE: $profile"
  aws --profile "$profile" "$@"
  echo "-------------------"
done
