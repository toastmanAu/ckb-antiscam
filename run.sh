#!/bin/bash
exec /usr/bin/node --dns-result-order=ipv4first /home/phill/ckb-antiscam/antiscam.js "$@"
