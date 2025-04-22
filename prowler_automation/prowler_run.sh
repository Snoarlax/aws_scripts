#!/bin/bash
sudo docker run -d -ti --rm -v $4:/home/prowler/output \
  --env AWS_ACCESS_KEY_ID=$1 \
  --env AWS_SECRET_ACCESS_KEY=$2 \
  --env AWS_SESSION_TOKEN=$3 toniblyx/prowler:latest
