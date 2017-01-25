####################################################################################################
#
# Zentera zCenter API
#
# Copyright (C) 2012-2016 Zentera Systems, Inc. - All Rights Reserved
#
# Zapi.py - Helper Functions for the Zentera API
#
####################################################################################################
#
# This demonstration software is provided by the copyright holders and contributors "as is" and 
# any express or implied warranties, including, but not limited to, the implied warranties of 
# merchantability and fitness for a particular purpose are disclaimed. In no event shall the 
# copyright holder or contributors be liable for any direct, indirect, incidental, special, 
# exemplary, or consequential damages (Including, but not limited to, procurement of substitute 
# goods or services; Loss of use, data, or profits; or business interruption) however caused and 
# on any theory of liability, whether in contract, strict liability, or tort (including negligence 
# or otherwise) arising in any way out of the use of this software, even if advised of the 
# possibility of such damage.
#
# This software is for demonstrations purposes only and is not supported by Zentera Systems, Inc.
#
####################################################################################################

import sys
import os
import hashlib
import hmac
import base64
import json
import requests
import httplib
import time

####################################################################################################
#
# Some Global Stuff
#
# Set ZapiDEBUG to True to Enable Debug Output
#
####################################################################################################

_ZapiDEBUG = False
_ZapiDEBUG = True

_ZapiErrorCodes = {
   'Ok':                            'Command carried out successfully',
   'AgentCannotUpgrade':            'The zLink Agent cannot upgrade',
   'AgentNoNeedUpgrade':            'The zLink Agent does not need an upgrade',
   'AppProfileIsBusy':              'App Profile is being accessed by another process. Please try again later',
   'AuthFailed':                    'Unrecognized API Key or API request HMAC verification failed',
   'BadLicense':                    'There is a problem with the current license file - either an expired license or no such license',
   'CloudDomainInUse':              'The requested Cloud Domain name alredy exists. Please try another one',
   'CmdFailed':                     'Command execution leads to some unforeseen failure',
   'CoipLanAlreadyExists':          'CoIP LAN routing flow already exists between the two components',
   'ComponentsMustInSameDomain':    'The Inline Streaming Device is not in the same Cloud Domain as the Server Group',
   'ConflictedCoipAddress':         'The CoIP address conflicts with other resource in the App Profile',
   'DuplicatedResourceName':        'The CoIP LAN name, Pool Tag or Server Group name already exists',
   'EndServerInUse':                'The requested End Server is already in use',
   'EndServerIsBusy':               'The End Servers to be added are currently accessed by another process. Please try again later',
   'EndServerNotAvailable':         'The requested End Server is not available',
   'EndServerNotFound':             'The requested End Server is not found',
   'FullOfDownloadStream':          'System does not have enoughresource to provide the download link',
   'InlinePolicyAlreadyApplied':    'Inline policy is already applied to this End Server',
   'InvalidArg':                    'The supplied command argument is unacceptable',
   'InvalidCoipAddress':            'The CoIP address is not valid',
   'InvalidComponentTypeInCoipLan': 'The Component type is notallowed in the CoIP LAN routing flow',
   'KeyDeact':                      'This API Key is currently deactivated',
   'MaxNumberOfIpsExceeded':        'End Servers to be added exceeds the number IPs allowed in the subnet of the server group',
   'NoCmdPerm':                     'You have no permissions to execute this command',
   'NonSa':                         'You have no permissions to execute service administration commands',
   'NoPerm':                        'You have no permissions to access the target resource(s)',
   'NoSuchCmd':                     'Command not recognized',
   'NoSuchJob':                     'The job does not exist',
   'NotEnoughEndServers':           'There are not enough available End Servers to complete this request',
   'ReqHttpIoErr':                  'Unable to read API request',
   'ReqMalformed':                  'Incomplete API request payload or inadequate arguments',
   'ReqMethodNotAllowed':           'HTTP POST or GET required',
   'ReqNotJson':                    'Content-Type "application/json" required',
   'ReqParseErr':                   'Internal server error while parsing API request',
   'SaOnly':                        'You are only entitled to execute service administration commands',
   'TargetNotFound':                'The requested resource does not exist',
   'UnexpectedErr':                 'Unexpected internal server error',
   'WinOsIdsNotAllowed':            'Failed to apply Tap flow to Windows End Server due to existing Inbound/Outbound policy',
   'WrongArgType':                  'Data type of one or more of the supplied command arguments is unacceptable',
   'WrongServerType':               'The End Server is not in the correct Server Pool'
}

####################################################################################################
#
# Retrieve the API Key and Passwords From the User's Environment
#
####################################################################################################

if os.getenv('ZENTERA_API_SKEY') == None:
   print "Error: ZENTERA_API_SKEY Environment Variable is Not Set"
   sys.exit()
else:
   _ZENTERA_API_SKEY = os.environ['ZENTERA_API_SKEY']

if os.getenv('ZENTERA_KID_SKEY') == None:
   print "Error: ZENTERA_KID_SKEY Environment Variable is Not Set"
   sys.exit()
else:
   _ZENTERA_KID_SKEY = os.environ['ZENTERA_KID_SKEY']

####################################################################################################
#
# Routines to Hide the Complexity of the API Requests
#
####################################################################################################

def makeZapiRequest(apiURL, command):
   "Craft a zCenter API Request"

   secret  = base64.standard_b64decode(_ZENTERA_API_SKEY)

   #
   # Calculate the HMAC signature = Base64( HMAC-SHA1( SecretKey, UTF8-Encoding-Of( RequestPayload ) ) )
   #
   hmacKey = hmac.new(secret, command.encode('UTF-8'), hashlib.sha1)
   hmacKey = hmacKey.digest().encode('base64').strip()

   #
   # Assemble the API Request
   #
   request = '{"request":' + command + ',"kid":"' + _ZENTERA_KID_SKEY + '","hmac":"' + hmacKey + '"}'

   if _ZapiDEBUG:
      print
      print ">>> Zapi Request  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
      print request
      print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
      print

   #
   # Make the API Request and Return the JSON Respons
   #
   headers = {'content-type': 'application/json'}
   Post = requests.post(apiURL, verify=False, data=request, headers=headers)
   info = json.loads(Post.content)

   if _ZapiDEBUG:
      print
      print "<<< Zapi Response <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
      print info
      print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
      print

   #
   # Error Checking
   #
   checkZapiStatus(info)

   return(info)

####################################################################################################

def checkZapiStatus(info):
   """
      Checks the Zapi return json against the known error codes.

      Returns True for 'Ok', False for all others
   """
   retVal = True
   
   if info['status'] != 'Ok':
      print
      print '  Oops:', _ZapiErrorCodes[info['status']]
      print info
      retVal = False
   
   return(retVal)

####################################################################################################

def printInfoList(info, prefix, indent):
   """
      Helper Function: Print a List of Info for Various Return Types
   """
   name = prefix + "Name"
   id   = prefix + "Id"

   if checkZapiStatus(info):
      for i in range(len(info['data'])):
	 print indent + '%4d: %s == %s' % (i, info['data'][i][name], info['data'][i][id])

####################################################################################################

def listEndServersByServerGroup(apiURL, appName, sgName):
   """
      Given an App Profile Name and Server Group Name, list the End Servers in the Group

      Returns the App Profile and Server Group IDs and a list of End Servers
   """
   appId = getAppProfileIdByAppProName(apiURL, appName)
   sgId  = getServerGroupIdByName(apiURL, appId, sgName)

   es = ServerGroup_listEndServers(apiURL, sgId)

   if checkZapiStatus(es):
      if len(es['data']) > 0:
         print
	 print "Idx : Hostname          PrivateIP     EndServerId"

	 for i in range(len(es['data'])):
	    print '%4d: %-15s %15s %s' % (i, es['data'][i]['hostname'],es['data'][i]['privateIp'], es['data'][i]['endServerId'])
      else:
         print
         print "   No Servers in '" + appName + "' --> '" + sgName + "'"

   return(appId, sgId, es)

####################################################################################################

def listEndServersByServerGroupId(apiURL, appId, appName, sgId, sgName):
   """
      Given an App Profile Name and Server Group Name, list the End Servers in the Group

      Returns the App Profile and Server Group IDs and a list of End Servers
   """

   es = ServerGroup_listEndServers(apiURL, sgId)

   if checkZapiStatus(es):
      if len(es['data']) > 0:
         print
	 print "Idx : Hostname          PrivateIP     EndServerId"

	 for i in range(len(es['data'])):
	    print '%4d: %15s %15s %s' % (i, es['data'][i]['hostname'],es['data'][i]['privateIp'], es['data'][i]['endServerId'])
      else:
         print
         print "   No Servers in '" + appName + "' --> '" + sgName + "'"

   return(appId, sgId, es)

####################################################################################################

def getEndServerList(info):
   """
      Converts a Zapi return json block into a simple list of End Server IDs
   """

   esList = []

   for i in range(len(info['data'])):
      esTemp = info['data'][i]['endServerId'].decode('ascii')
      esList.append(esTemp)

   return(esList)

####################################################################################################

def errorNYI(funcName):
   """
      Handle Not Yet Implemented functions politely
   """

   print
   print "The function '%s' is not yet implemented - Exiting" % funcName
   print
   print "Please use the native API calls for this function"
   print
   sys.exit()

####################################################################################################
#
# Application Profile Commands
#
####################################################################################################

def AppProfile_activate(apiURL, apId):
   """
      Activates an Application Profile
   """

   req = {
      'cmd':'$AppProfile.activate',
      'args':{
	 'appProfileId': apId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def AppProfile_addCoipLan(apiURL, apId, lName, frId, toId, tcp, udp, icmp):
   """
      Adds a CoIP LAN routing flow between components within an Application Profile
   """

   req = {
      'cmd':'$AppProfile.addCoipLan',
      'args':{
         'appProfileId': apId,
	 'coipLanName': lName,
	 'components':{
	    'from': frId,
	    'to': toId
	 },
	 'protocol':{
	    'tcp': tcp,
	    'udp': udp,
	    'icmp': icmp
	 }
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def AppProfile_addInlineDevice(apiURL, apId, esId, coipAddr):
   """
      Adds an Inline Streaming Device to an Application Profile

      Returns the Inline Device Id
   """

   req = {
      'cmd':'$AppProfile.addInlineDevice',
      'args':{
	 'appProfileId': apId,
	 'inlineStreamingType': 'inlineStreamingDevice',
	 'endServerId': esId,
	 'coipAddress':  coipAddr
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['inlineDeviceId'])

####################################################################################################

def AppProfile_addServerGroup(apiURL, apId, ptName, sgName, fromCoIP, toCoIP):
   """
      Adds a Server Group to an Application Profile

      Returns the new Server Group Id
   """

   req = {
      'cmd':'$AppProfile.addServerGroup',
      'args':{
	 'appProfileId': apId,
	 'poolTag': ptName,
	 'serverGroupName': sgName,
	 'coipSubnet': {
	    'from': fromCoIP,
	    'to': toCoIP
        }
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['serverGroupId'])

####################################################################################################

def AppProfile_create(apiURL, apName, assignmentType):
   """
      Creates and activates a new Application Profile

      Returns the App Profile Id
   """

   req = {
      'cmd':'$AppProfile.create',
      'args':{
	 'appProfileName': apName,
	 'coipAssignment': assignmentType
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   if not checkZapiStatus(info):
      sys.exit(-1)

   return(info['data']['appProfileId'])

####################################################################################################

def AppProfile_deactivate(apiURL, appProfileId):
   """
      Deactivates an application profile
   """

   req = {
      'cmd':'$AppProfile.deactivate',
      'args':{
	 'appProfileId': appProfileId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def AppProfile_delete(apiURL, appProfileId):
   """
      Deletes the specified Application Profile
   """

   req = {
      'cmd':'$AppProfile.delete',
      'args':{
	 'appProfileId': appProfileId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def AppProfile_listInlineDevices(apiURL, appProfileId):
   """
      Lists the Inline Devices that are currently associated with the specified Application Profile
   """

   req = {
      'cmd':'$AppProfile.listInlineDevices',
      'args':{
	 'appProfileId': appProfileId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def AppProfile_listServerGroups(apiURL, appProfileId):
   """
      Lists the Server Groups that are currently associated with the specified Application Profile
   """

   req = {
      'cmd':'$AppProfile.listServerGroups',
      'args':{
	 'appProfileId': appProfileId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################
#
# Cloud Domain Commands
#
####################################################################################################

def CloudDomain_create(apiURL, cdName, desc, monInt):
   """
      Creates a Cloud Domain

      Returns the Cloud Domain Id
   """

   req = {
      'cmd':'$CloudDomain.create',
      'args':{
         'cloudDomainName': cdName,
         'description': desc,
         'monitorInterval': monInt
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['cloudDomainId'])

####################################################################################################

def CloudDomain_delete(apiURL, cdId):
   """
      Deletes a Cloud Domain
   """

   req = {
      'cmd':'$CloudDomain.delete',
      'args':{
	 'cloudDomainId': cdId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def CloudDomain_listCloudServerPools(apiURL, cdId):
   """
      Lists the Cloud Server Pools that belong to a specific Cloud Domain
   """

   req = {
      'cmd':'$CloudDomain.listCloudServerPools',
      'args':{
	 'cloudDomainId': cdId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def CloudDomain_listFabricServerPools(apiURL, cdId, fsType):
   """
      Lists the Fabric Server Pools which belongs to a specific Cloud Domain
   """

   req = {
      'cmd':'$CloudDomain.listCloudFabricPools',
      'args':{
         'cloudDomainId': cdId,
         'fabricServerType':fsType
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################
#
# Cloud Server Pool Commands
#
####################################################################################################

def CloudServerPool_create(apiURL, ptName, ptDesc, cdId):
   """
      Creates a Cloud Server Pool

      Returns Cloud Server Pool Id
   """

   req = {
      'cmd':'$CloudServerPool.create',
      'args':{
         'poolTag': ptName,
	 'description': ptDesc,
	 'cloudDomainId': cdId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['poolTag'])

####################################################################################################

def CloudServerPool_delete(apiURL, poolTag):
   """
      Deletes a Cloud Server Pool
   """

   req = {
      'cmd':'$CloudServerPool.delete',
      'args':{
         'poolTag': poolTag
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def CloudServerPool_getZlinkDownloadUrl(apiURL, poolTag, osFlavor):
   """
      Gets zLink download URL for the Cloud Server Pool
   """

   req = {
      'cmd':'$CloudServerPool.getZlinkDownloadUrl',
      'args':{
	 'poolTag': poolTag,
	 'os': osFlavor
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['downloadUrl'])

####################################################################################################

def CloudServerPool_listEndServers(apiURL, poolTag, usable):
   """
      Lists available Cloud Servers in a Server Pool
   """

   req = {
      'cmd':'$CloudServerPool.listEndServers',
      'args':{
	 'poolTag': poolTag,
	 'usable': usable
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################
#
# Customer Commands
#
####################################################################################################

def Customer_getControllerCertificate(apiURL):
   """
      Returns the Controller's Certificate
   """

   req = {
      'cmd':'$Customer.getControllerCertificate',
      'args': None
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def Customer_listAppProfiles(apiURL):
   """
      Lists the Application Profiles that the current user is entitled to access
   """

   req = {
      'cmd':'$Customer.listAppProfiles',
      'args':{
	 'active': 'yes'
      }
   }

   reqs = json.dumps(req)
   
   info = makeZapiRequest(apiURL, reqs)
   
   return(info)

####################################################################################################

def getAppProfileIdByAppProName(apiURL, appProName):
   """
      Helper Function: Returns the App Profile ID for the Named App Profile
   """

   info = makeZapiRequest(apiURL, '{"cmd":"$Customer.listAppProfiles","args":{"active":"yes"}}')
   rets = None

   if info['status'] != 'Ok':
      print "   Some kind of Error in getAppProfileByName()"
      print "  ", info['message']
   else:
      for i in range(len(info['data'])):
         # print info['data'][i]['appProfileName']
         if info['data'][i]['appProfileName'] == appProName:
	    rets = info['data'][i]['appProfileId']

   return(rets)

####################################################################################################

def Customer_listCloudDomains(apiURL):
   """
      Lists the Cloud Domains that the current user is entitled to access
   """

   req = {
      'cmd':'$Customer.listCloudDomains',
      'args': None
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def getCloudDomainIdByName(apiURL, cdName):
   """
      Helper Function: Given a Cloud Domain Name, return the Cloud Domain Id
   """
   info = Customer_listCloudDomains(apiURL)

   rets = None

   if info['status'] != 'Ok':
      print "   Some kind of Error in getCloudDomainIdByName()"
      print "  ", info['message']
   else:
      for i in range(len(info['data'])):
	 # print info['data'][i]['cloudDomainName']
	 if info['data'][i]['cloudDomainName'] == cdName:
	    rets = info['data'][i]['cloudDomainId']
	    # print rets

   return(rets)

####################################################################################################
#
# End Server Commands
#
####################################################################################################

def EndServer_addInlinePolicy(apiURL, esId, ipId, cidr):
   """
      Applies a security inline streaming policy to an End Server
   """

   req = {
      'cmd':'$EndServer.addInlinePolicy',
      'args':{
	 'endServerId': esId,
	 'inlinePolicyId': ipId,
	 'cidr': cidr
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def EndServer_deleteInlinePolicy(apiURL):
   """
      Deletes a security inline streaming policy from an End Server

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """

   req = {
      'cmd':'$EndServer.deleteInlinePolicy',
      'args':{
	 'arg1': 'arg1v',
	 'arg2': 'arg2v'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def EndServer_getDetails(apiURL, esId):
   """
      Get detailed information about an End Server
   """

   req = {
      'cmd':'$EndServer.getDetails',
      'args':{
	 'endServerId': esId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def EndServer_listInlinePolicies(apiURL):
   """
      Lists security inline streaming policies applied to an End Server

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """

   req = {
      'cmd':'$Customer.listInlinePolicies',
      'args':{
	 'arg1': 'arg1v',
	 'arg2': 'arg2v'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def EndServer_queryRegistrationStatus(apiURL, jobId):
   """
      Queries the completion status of an End Server registration job previously submitted using the command $EndServer.register

      Loops until the return status is either 'done' or 'failed'. If 'done' then returns the End Server Id

      Note: Terrible implementation! This does not allow concurrent jobs
   """

   req = {
      'cmd':'$EndServer.queryRegistrationStatus',
      'args':{
	 'jobId': jobId
      }
   }

   reqs = json.dumps(req)
   
   loopFlag = False

   while loopFlag == False:
      info = makeZapiRequest(apiURL, reqs)

      time.sleep(1)

      if info['data']['jobStatus'] == 'done':
         loopFlag = True
	 rets = info['data']['endServerId']

      if info['data']['jobStatus'] == 'failed':
         loopFlag = False
	 rets = 'Job Failed'

   return(rets)

####################################################################################################

def EndServer_register(apiURL, poolTag, hostname, sshId, sshPasswd, sshPrivKey, sshPort):
   """
      Registers a computer server (designated by the hostname parameter) with the specified 
      Cloud/Fabric Server Pool (designated by the poolTag parameter) via zCenter's 
      Auto-Provisioning mechanism. 

      For the sshPasswd  method, supply a password and leave the sshPrivKey set to ''
      For the sshPrivKey method, supply a private key and leave the sshPasswd set to ''

      If both sshPasswd and sshPrivKey are set, the sshPrivKey method is preferred
      
      If the registration succeeds, the server becomes a member of that Server Pool, 
      and is regarded as an End Server managed by zCenter
   """

   if len(sshPrivKey) > 0:
      # print "Key  Method"
      req = {
	 'cmd':'$EndServer.register',
	 'args':{
	    'poolTag': poolTag,
	    'hostname': hostname,
	    'sshId': sshId,
	    'sshPrivateKey': sshPrivKey,
	    'sshPort': sshPort
	 }
      }
   else:
      # print "Password Method"
      req = {
	 'cmd':'$EndServer.register',
	 'args':{
	    'poolTag': poolTag,
	    'hostname': hostname,
	    'sshId': sshId,
	    'sshPassword': sshPasswd,
	    'sshPort': sshPort
	 }
      }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def getPrivKeyFromFile(fileName):
   """
      Helper Function: Return the contents of the fileName into a string
   """

   f = open(fileName, 'r')
   pk = f.read()
   f.close()

   return pk

####################################################################################################

def EndServer_unregister(apiURL, esId):
   """
      Unregisters an End Server from Cloud or Fabric Server Pool
   """

   req = {
      'cmd':'$EndServer.unregister',
      'args':{
	 'endServerId': esId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def EndServer_upgradeZlink(apiURL):
   """
      Upgrades zLink on an End Server to the latest version

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """

   req = {
      'cmd':'$Customer.upgradeZlink',
      'args':{
	 'arg1': 'arg1v',
	 'arg2': 'arg2v'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################
#
# Fabric Server Pool Commands
#
####################################################################################################

def FabricServerPool_create(apiURL, ptName, ptDesc, cdId):
   """
      Creates a Fabric Server Pool

      Returns Fabric Server Pool Id
   """

   req = {
      'cmd':'$FabricServerPool.create',
      'args':{
	 'poolTag': ptName,
	 'description': ptDesc,
	 'fabricServerType':'inlineStreamingDevice',
	 'cloudDomainId': cdId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['poolTag'])

####################################################################################################

def FabricServerPool_delete():
   """
      Deletes a Fabric Server Pool

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """

   req = {
      'cmd':'$FabricServerPool.delete',
      'args':{
         'arg1': 'arg1v',
         'arg2': 'arg2v'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def FabricServerPool_getZlinkDownloadUrl():
   """
      Gets zLink download URL for a Fabric Server Pool

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """

   req = {
      'cmd':'$FabricServerPool.getZlinkDownloadUrl',
      'args':{
         'arg1': 'arg1v',
         'arg2': 'arg2v'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def FabricServerPool_listEndServers(apiURL, poolTag, usable):
   """
      Lists available Fabric servers by Server Pool
   """

   req = {
      'cmd':'$FabricServerPool.listEndServers',
      'args':{
	 'poolTag': poolTag,
	 'usable': usable
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################
#
# Server Group Commands
#
####################################################################################################

def ServerGroup_addInlinePolicy(apiURL, sgId, pName, pType, ilId, dIps, dir, proto):
   """
      Defines a security inline streaming policy to a Server Group

      Returns the Inline Policy Id
   """
   
   req = {
      'cmd':'$ServerGroup.addInlinePolicy',
      'args':{
	 'serverGroupId': sgId,
	 'policyName': pName,
	 'policyType': pType,
	 'inlineDeviceId': ilId,
	 'destinationIps': dIps,
	 'direction': dir,
	 'protocol': proto
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info['data']['inlinePolicyId'])

####################################################################################################

def ServerGroup_deleteInlinePolicy(apiURL):
   """
      Deletes a security inline streaming policy from a Server Group

      Zapi Helper Function Not Yet Implemented - Please Use Native API Function
   """
   
   req = {
      'cmd':'$ServerGroup.deleteInlinePolicy',
      'args':{
	 'arg1': 'arg1'
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)



####################################################################################################

def ServerGroup_autoAddEndServers(apiURL, sgId, cnt):
   """
      Automatically adds 'cnt' End Servers to a Server Group
   """
   
   req = {
      'cmd':'$ServerGroup.autoAddEndServers',
      'args':{
	 'serverGroupId': sgId,
	 'numServers': cnt
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def ServerGroup_manualAddEndServers(apiURL, sgId, esList):
   """
      Manually adds End Servers to a Server Group

      Zapi Helper Function Implemented - Awaiting Patch for the API Function
   """
   
   req = {
      'cmd':'$ServerGroup.manualAddEndServers',
      'args':{
	 'serverGroupId': sgId,
	 'endServers':[ '"' + esList + '"']
      }
   }

   errorNYI(req['cmd'])
   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def ServerGroup_listEndServers(apiURL, sgId):
   """
      Returns the End Servers in a Server Group
   """
   
   req = {
      'cmd':'$ServerGroup.listEndServers',
      'args':{
	 'serverGroupId': sgId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def getServerGroupIdByName(apiURL, appId, sgName):
   """
      Helper Function: Find a Server Group's ID by the Server Group's Name
   """

   rets = None

   #
   # Get the List of Server Group
   #
   sg = AppProfile_listServerGroups(apiURL, appId)

   #
   # Iterate Through the List Searching for the Matching Server Group
   #
   if sg['status'] != 'Ok':
      print "   Some kind of Error in getServerGroupIdByName()"
      print "  ", sg['message']
   if checkZapiStatus(sg):
      for i in range(len(sg['data'])):
         # print sg['data'][i]['serverGroupName']
         if sg['data'][i]['serverGroupName'] == sgName:
	    rets = sg['data'][i]['serverGroupId']

   return(rets)

####################################################################################################

def ServerGroup_listInlinePolicies(apiURL, sgId):
   """
      Lists security inline streaming policy of a Server Group
   """
   
   req = {
      'cmd':'$ServerGroup.listInlinePolicies',
      'args':{
	 'serverGroupId': sgId
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)

   return(info)

####################################################################################################

def ServerGroup_removeEndServers(apiURL, sgId, esList):
   """
      Remove End Servers from a Server Group
   """

   req = {
      'cmd':'$ServerGroup.removeEndServers',
      'args':{
	 'serverGroupId': sgId,
	 'endServers': esList
      }
   }

   reqs = json.dumps(req)
   info = makeZapiRequest(apiURL, reqs)
