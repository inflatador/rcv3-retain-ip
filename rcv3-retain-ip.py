#!/usr/bin/env python3
# rcv3-retain-ip.py
# given region and Cloud Server ID,
# retains public IP associated with that server
# version: 0.0.1a
# Copyright 2020 Brian King
# License: Apache

from getpass import getpass
import json
import keyring
import logging
import os
import plac
import requests
import sys
import time

requests.packages.urllib3.disable_warnings()

def find_endpoints(auth_token, headers, region, desired_service="rackconnect"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]

    for service in endpoints:
        if desired_service == service["name"] and region == service["region"]:
            desired_endpoint = service["publicURL"]

    return desired_endpoint

def getset_keyring_credentials(username=None, password=None):
    #Method to retrieve credentials from keyring.
    print (sys.version_info.major)
    username = keyring.get_password("rcv3cloud", "username")
    print ("Detected username as {}".format(username))
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("rcv3cloud", 'username', username)
            print ("Username value saved in keychain as rcv3cloud username.")
        elif sys.version_info.major >= 3:
            username = input("Enter Rackspace Username: ")
            keyring.set_password("rcv3cloud", 'username', username)
            print ("Username value saved in keychain as rcv3cloud username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("rcv3cloud", "password")
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("rcv3cloud", 'password' , password)
        print ("API key value saved in keychain as rcv3cloud password.")
    return username, password
# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]
    print (f"Got token {auth_token} !")
    headers = ({'content-type': 'application/json', 'Accept': 'application/json',
    'X-Auth-Token': auth_token})

    return auth_token, headers

def find_pub_ip(rc_ep, headers, srv_id):
    querystuff = ({ 'cloud_server_id' : srv_id })
    pub_ip_route = "{}/public_ips".format(rc_ep)
    pub_ip_req = requests.get(url = pub_ip_route, 
                              headers = headers, params = querystuff)
    pub_ip_req.raise_for_status()
    # print (pub_ip_req.json())
    if len(pub_ip_req.json()) == 1:
        pub_ip = pub_ip_req.json()[0]["public_ip_v4"]
        server_name = pub_ip_req.json()[0]["cloud_server"]["name"]
        pub_ip_id = pub_ip_req.json()[0]["id"]
        pub_ip_status = pub_ip_req.json()[0]["status"]
        pub_ip_retention = pub_ip_req.json()[0]["retain"]
        # return pub_ip_url, pub_ip, server_name, pub_ip_id, pub_ip_status, pub_ip_retention, src_rcv3_endpoint
    #if we make it through our loop, the source server IP doesn't have a pub IP.
    elif len(pub_ip_req.json()[0]) == 0:
            print ("Error! Cloud Server UUID %s does not have a RackConnect v3 public IP." % (srv_id) )
            sys.exit(1)
    if pub_ip_status != "ACTIVE":
        print ("Error! Expected Public IP {} status to be ACTIVE, but it's {} ."
              "Exiting!".format(pub_ip, pub_ip_status))
    if pub_ip_retention is True:
        print ("Pub IP {} is already retained. Exiting...".format(pub_ip))
        sys.exit(1)
    
    return pub_ip, pub_ip_id, pub_ip_route

def retain_pub_ip(headers, pub_ip, pub_ip_id, pub_ip_route):
    print ("Setting retain flag True on pub IP {}".format(pub_ip))
    retain_route = "{}/{}".format(pub_ip_route, pub_ip_id)
    retain_data = { 'retain': 'true' }
    enable_retain = requests.patch(url=retain_route, headers=headers, 
                    json=retain_data)
    enable_retain.raise_for_status()
    print ("OK, I set retain flag True on pub IP {}. Now verifying...".format(pub_ip))
    verify_retain = requests.get(url=retain_route, headers=headers)
    verify_retain.raise_for_status()
    print (verify_retain.json())

@plac.annotations(
region=plac.Annotation("RackConnect region"),
srv_id=plac.Annotation("Cloud Server UUID")
                )

def main(region, srv_id):

    username, password = getset_keyring_credentials()

    auth_token, headers = get_auth_token(username, password)
                                                      
    rc_ep = find_endpoints(auth_token, headers, region, desired_service="rackconnect")

    pub_ip, pub_ip_id, pub_ip_route = find_pub_ip(rc_ep, headers, srv_id)

    retain_pub_ip(headers, pub_ip, pub_ip_id, pub_ip_route)


if __name__ == '__main__':
    import plac; plac.call(main)
