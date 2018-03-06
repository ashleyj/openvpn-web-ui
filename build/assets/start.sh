#!/bin/bash

set -e
OVDIR=/etc/openvpn

cd /opt/

if [ ! -f $OVDIR/.provisioned ]; then
  echo "Preparing certificates"
  mkdir -p $OVDIR
  ./scripts/generate_ca_and_server_certs.sh
  openssl dhparam -dsaparam -out $OVDIR/dh2048.pem 2048
  if [ ! -d /opt/openvpn-gui/ssl ]; then 
	  mkdir -p /opt/openvpn-gui/ssl
  fi
  cp /etc/openvpn/keys/server.crt /opt/openvpn-gui/ssl/ssl.crt
  cp /etc/openvpn/keys/server.key /opt/openvpn-gui/ssl/ssl.key
  touch $OVDIR/.provisioned
fi
cd /opt/openvpn-gui
mkdir -p db
./openvpn-web-ui
echo "Starting!"

