#!/bin/bash

# Edit shroom.server to your hostname
openssl req -x509 -newkey rsa:4096 -keyout keys/key.pem -out keys/cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=shroom.server"