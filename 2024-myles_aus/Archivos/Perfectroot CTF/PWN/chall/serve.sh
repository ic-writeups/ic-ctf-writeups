#!/bin/bash
socat \
-T60 \
TCP-LISTEN:1235,reuseaddr,fork \
EXEC:"timeout 60 ./chall"
