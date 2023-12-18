#!/bin/bash
  
# Copy the prepared resolv.conf file
cp /etc/resolv.conf.override /etc/resolv.conf

echo "export PS1='$(whoami)@user: [$(pwd)] $ '" >> $HOME/.bashrc

# Start the shell
/bin/bash

