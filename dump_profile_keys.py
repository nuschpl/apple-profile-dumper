#!/usr/bin/python
# -*- coding: utf-8 -*-

#requires pyasn1, python-openssl

'''AppleProfileDumper by nusch'''

import os,sys
from pyasn1.codec.cer.decoder import decode as asn1decode
from base64 import b64decode
from xml.dom import minidom

from OpenSSL.crypto import load_certificate, load_pkcs12, FILETYPE_ASN1
from OpenSSL._util import lib as cryptolib
#from Crypto.PublicKey import RSA

import code

OUT_DIR='out'

class AppleProfileDumper(object):
  PKCS7_OID='1.2.840.113549.1.7.2'
  def __init__(self, ):
    if len(sys.argv)!=2:
      self.usage()
      sys.exit()

    self.out_dir = os.path.join(os.getcwd(), OUT_DIR)
    if not os.path.exists(self.out_dir):
      os.makedirs(self.out_dir)

    self.FILE=sys.argv[1]
    content = open(self.FILE).read()
    mobileconfig = asn1decode(content)[0]
    if(str(mobileconfig[0])!=self.PKCS7_OID):
      print "Bad format: %r" % (str(mobileconfig[0]))
      print self.PKCS7_OID
      sys.exit(1)
    else:
      con=mobileconfig[1]
      xml_profile=str(con[2][1])
      self.parseXMLConfig(xml_profile)

  def dom_dict_to_list(self, parent_node):
    dct = {}
    #raw_input(parent_node.toxml())
    idict = iter(list(parent_node.childNodes))
    for elem in idict:
        if elem.nodeName=="key":
            val=idict.next()
            name = elem.firstChild.data
            if val.nodeName in ("string", "integer", "data"):
               try:
                  dct[name]=val.firstChild.data
               except AttributeError:
                  if not val.nodeValue:
                     dct[name]="" 
               #print("val.firstChild.data attempt. Debug")
               #code.interact(local=locals())
               #
               #print "%s: %s" % ( name, val.firstChild.data )
            elif val.nodeName in ("true", "false"):
               dct[name]=val.nodeName
               #print "%s: %s" % ( name, val.nodeName )
            elif val.nodeName in ("array"):
               #raw_input(val.toxml())
               dct[elem.firstChild.data] = []
               for d in val.childNodes:
                  if d.nodeName == "array":
                    dct[elem.firstChild.data].append(d)
                  elif d.nodeName == "dict":
                    dct[elem.firstChild.data].append(self.dom_dict_to_list(d))
                  elif d.nodeName in ("string", "integer"):
                    dct[elem.firstChild.data].append(d.firstChild.data)
                  else:
                    raise(KeyError("unexcepted node name: %s" % (d.nodeName)))
               #print "%s: %s" % ( name, val.nodeName )
            elif val.nodeName in ("dict"):
               dct[elem.firstChild.data] = {}
               #raw_input(elem.toxml())
               try:
                 dct[elem.firstChild.data] = self.dom_dict_to_list(val)
                 #dct[elem.firstChild.data] = val.toxml()
                 #print "%s: %s" % ( name, val.nodeName )
               except ValueError:
                 print("DEBUG ERROR: dct[elem.firstChild.data].append(self.dom_dict_to_list(d))")
                 code.interact(local=locals())
               #print "%s: %s" % ( name, val.nodeName )
            else:
               raise(ValueError("Not string, integer, type: %s" % (val.nodeName) ) )
    #code.interact(local=locals())
    #if not dct:
    #   return parent_node.toxml()
    return dct

  def parseXMLConfig(self, xml_text):
    #code.interact(local=locals())
    dom = minidom.parseString(xml_text)
    plist = dom.getElementsByTagName("plist")[0]
    dic = dom.getElementsByTagName("dict")[0]
    payloads=()
    config = self.dom_dict_to_list(dic)
    payload= config['PayloadContent']
    self.listPayloads([config])
    #print payload[3]['EAPClientConfiguration']

    for key in dic.getElementsByTagName("key"):
      k_str = key.firstChild.data
      if k_str=="PayloadType":
        payload_type_str=key.nextSibling.firstChild.data
        print("PayloadType: %s " % (payload_type_str) )

  def listPayloads(self, payloads):
    for payload in payloads:
      print payload['PayloadType']
      if payload['PayloadType']=="Configuration":
        print "Name: %s\nOrganization: %s\nScope: %s\n" % (payload["PayloadDisplayName"], payload["PayloadOrganization"], payload["PayloadScope"])
        print "=========================================="
        self.listPayloads(payload['PayloadContent'])
      else:
        self.printPayload(payload)

  def printPayload(self, payload):
    password=None
    if "PayloadDisplayName" in payload:
      print "\tName: %s" % (payload.pop("PayloadDisplayName") )
    if "PayloadVersion" in payload:
      print "\tVersion: %s" % (payload.pop("PayloadVersion") )
    if "PayloadDescription" in payload:
      print "\tDescription: %s" % (payload.pop("PayloadDescription") )
    if "PayloadUUID" in payload:
      print "\tUUID: %s" % (payload.pop("PayloadUUID") )
    if "Password" in payload:
      password=payload.pop("Password")
      print "\tPassword: %s" % (password)
    if "RemovalPassword" in payload:
      print "\tRemoval password: %s" % (payload.pop("RemovalPassword") )
    #print("\tDEBUG: unparsed keys: %s" % (repr(payload.keys())))
    for key in payload.keys():
      if key not in ("updated_at_xid", "PayloadType", "PayloadContent"):
        print ("\t%s: %r" % (key, payload[key]))
    if payload["PayloadType"] in ("com.apple.security.pkcs1", "com.apple.security.root"):
      self.parsePKCS1Payload(payload["PayloadContent"], dump=True)
    elif payload["PayloadType"] in ("com.apple.security.pkcs12"):
      self.parsePKCS12Payload(payload["PayloadContent"], password=password, dump=True)
    elif payload["PayloadType"] not in ("com.apple.profileRemovalPassword", "com.apple.mobiledevice.passwordpolicy", "com.apple.wifi.managed", ""):
      print("DEBUG: payload type %s support unimplemented" % (payload["PayloadType"]))

  def parsePKCS1Payload(self, node, dump=False, display=False):
    key_der_str=b64decode(node)
    cert = load_certificate(FILETYPE_ASN1, key_der_str)
    print "Subject: %s\nIssuer: %s\n" % (cert.get_subject(), cert.get_issuer())
    name = "%s/%s.crt" % (self.out_dir, cert.get_subject().get_components()[-1][1] )
    if dump:
       open("%s" % (name), 'w').write(key_der_str)
       if display:
          os.system("gcr-viewer '%s' &" % (name, ))

  def parsePKCS12Payload(self, node, password=None, dump=False, display=False):
    key_der_str=b64decode(node)


    pkcs12 = load_pkcs12(key_der_str, password)
    cert = pkcs12.get_certificate()

    print "Subject: %s\nIssuer: %s\n" % (cert.get_subject(), cert.get_issuer())
    name = "%s/%s.pfx" % (self.out_dir, cert.get_subject().get_components()[-2][1] )
    if dump:
       open("%s" % (name), 'w').write(key_der_str)
       if display:
          os.system(name)

  def usage(self, ):
    print("Usage: %s file.mobileconfig" % sys.argv[0] )

apd = AppleProfileDumper()
