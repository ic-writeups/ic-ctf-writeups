#!/bin/bash

sudo docker build -t chall .

sudo docker run -dit --name challenge -p 1235:1235 chall
