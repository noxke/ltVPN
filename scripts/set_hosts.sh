#!/bin/bash

route del default
echo "10.12.1.1     vpn.example.com" >> /etc/hosts
