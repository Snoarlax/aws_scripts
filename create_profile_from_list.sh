#!/bin/bash
for arn in $(
  cat $1
); do
  # Creates a profile name equal to the account id of the aws account
  ./create_profile_from_arn.sh $arn "$(echo $arn | cut -d ':' -f 5)"
done
