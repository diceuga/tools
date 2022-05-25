from socket import *
from bitstring import *
import struct
import datetime
import influxdb
import ipaddress
import os
import json
import datetime
import yaml
import pprint
from elasticsearch import Elasticsearch
from ipfixdef import IPFIX_DEF

# functions ------------------------------------------------
def getint(l,s):
  r = 0
  if (l==4):
    nh = struct.unpack('>L', message[s:s+l]); r = nh[0];
  elif (l==2):
    nh = struct.unpack('>H', message[s:s+l]); r = nh[0];
  elif (l==1):
    nh = struct.unpack('>B', message[s:s+l]); r = nh[0];
  elif (l==8):
    nh = struct.unpack('>LL', message[s:s+l]);
    r  = (nh[0]<<32) + nh[1]
  return r

def getipv6(l,s):
  nh = struct.unpack('>LLLL', message[s:s+l]);
  return(str(ipaddress.IPv6Address((nh[0]<<96)+(nh[1]<<64)+(nh[2]<<32)+nh[3])))

def getipv4(l,s):
  nh = struct.unpack('>BBBB', message[s:s+l]);
  return(str(ipaddress.IPv4Address((nh[0]<<24)+(nh[1]<<16)+(nh[2]<<8)+nh[3])))

def getdatefrommilli(t):
  return (str(datetime.datetime.fromtimestamp(timeadj + t/1000)))

  
# env ------------------------------------------------------
## get from config.yaml
conf = {}
if ( os.path.isfile("config.yaml") ):
  with open("config.yaml", "r") as f:
    conf = yaml.load(f)

# get from env
envd = os.environ

# prefer config.yaml
# local dump
dump = bool(conf["flow_dump"]) if ( "flow_dump" in conf ) else bool(envd["flow_dump"]) if ( "flow_dump" in envd ) else False
pp = pprint.PrettyPrinter(indent=4)

# port
port = int(conf["flow_port"]) if ( "flow_port" in conf ) else int(envd["flow_port"]) if ( "flow_port" in envd ) else 9005

# influxdb
idbflg = bool(conf["flow_idb"])  if ( "flow_id"   in conf ) else bool(envd["flow_idb"]) if ( "flow_idb" in envd ) else False
if ( idbflg ):
  idbaddr = conf["flow_idbaddr"]      if ( "flow_idbaddr" in conf ) else envd["flow_idbaddr"]      if ( "flow_idbaddr" in envd ) else ""
  idbport = int(conf["flow_idbport"]) if ( "flow_idbport" in conf ) else int(envd["flow_idbport"]) if ( "flow_idbport" in envd ) else 0
  idbdbn  = conf["flow_idbdbn" ]      if ( "flow_idbdbn"  in conf ) else envd["flow_idbdbn"]       if ( "flow_idbdbn" in envd )  else ""
else:
  idbaddr = ""
  idbport = 0
  idbdbn  = ""

if ( ( idbaddr == "" ) or ( idbport == 0 ) or ( idbdbn == "") ):
 idbflg = False

# elastic search
elaflg = bool(conf["flow_ela"])  if ( "flow_ela"  in conf ) else bool(envd["flow_ela"]) if ( "flow_ela" in envd ) else False 
if ( elaflg ):
  elaaddr = conf["flow_elaaddr"]      if ( "flow_elaaddr" in conf ) else envd["flow_elaaddr"]      if ( "flow_elaaddr" in envd ) else ""
  elaport = int(conf["flow_elaport"]) if ( "flow_elaport" in conf ) else int(envd["flow_elaport"]) if ( "flow_elaport" in envd ) else 0
  elauser = conf["flow_elauser"]      if ( "flow_elauser" in conf ) else envd["flow_elauser"]      if ( "flow_elauser" in envd ) else ""
  elapass = conf["flow_elapass"]      if ( "flow_elapass" in conf ) else envd["flow_elapass"]      if ( "flow_elapass" in envd ) else ""
  elaidx = conf["flow_elaidx"]        if ( "flow_elaidx" in conf )  else envd["flow_elaidx"]       if ( "flow_elaidx" in envd )  else ""
else:
  elaaddr = ""
  elaport = 0
  elauser = ""
  elapass = ""
  elaidx  = ""

if ( ( elaaddr == "" ) or ( elaport == 0 ) or ( elauser == "" ) or ( elapass == "" ) or ( elaidx == "" ) ):
  elaflg = False

# time_adjust(def JST(+9))
timeadj  = bool(conf["flow_time"]) if ( "flow_time" in conf ) else bool(envd["flow_time"]) if ( "flow_time" in envd ) else 32400



##### bind/connection
#host   = '10.2.255.102' #accept dest address,  is any
host   = '0.0.0.0' #accept dest address,  is any
locaddr = (host,port)   
sock = socket(AF_INET, SOCK_DGRAM); sock.bind(locaddr);

# connect influxdb
if ( idbflg ):
  idb = influxdb.InfluxDBClient(host=idbaddr, port=idbport)
  idb.switch_database(idbdbn)

# ela
if ( elaflg ):
  es = Elasticsearch("http://"+ elaaddr + ":" + str(elaport) ,basic_auth=(elauser, elapass))


# loop
dtp = {}		# data template
otp = {}		# option template
op  = {}		# option record
M_SIZE = 65535          # buffer

while True:
  try:
    message, cli_addr = sock.recvfrom(M_SIZE)
    sa = cli_addr[0]	# source address
    if not ( sa in dtp ): dtp[sa] = {}
    if not ( sa in otp ): otp[sa] = {}
    if not ( sa in op ):  op[sa]  = {}
    
    # netflow header(for x)
    nh = struct.unpack('>HHLLLHH', message[0:20])
    etime= nh[2] 	# export time
    etime_f  = datetime.datetime.fromtimestamp(etime).isoformat()
    seq  = nh[3]         # Sequence
    did  = nh[4]         # doamin id
    sid  = nh[5]         # set id
    slen = nh[6]         # set len

    doccommon = {
      "host"   : sa,
      "domainid" :did,
      "setid": sid,
      "sequence" : seq,
      "@timestamp" : etime_f,
      "exporttime": etime
    }

    #template
    if not ( did in dtp[sa] ): dtp[sa][did] ={} 
    if not ( did in otp[sa] ): otp[sa][did] ={}
    #option
    if not ( did in op[sa] ):  op[sa][did]  ={}; op[sa][did]["samplingInterval"]  = -1;

    # Datatamplate
    if (sid == 2 ):
      rh = struct.unpack('>HH', message[20:24])
      tid = rh[0]
      fn  = rh[1]
      if not ( tid in dtp[sa][did] ): dtp[sa][did][tid] = {}
      
      wktp = {};
      wktp["exporttime"] = etime;
      wktp["len"]        = 0
      wktp["count"]      = fn;
      wktp["format"]     = []

      doc = doccommon;
      doc.update({"type": "Data Template", "templateid": tid,"count": fn});

      i=0;
      pos = 24
      for i in range(fn):
        E = struct.unpack('>HH', message[pos:(pos+4)])
        ebit = int(bin((E[0] >> 15) & 0b1),0)
        eid  = int(bin((E[0] ) & 0b0111111111111111),0)
        elen = E[1]
        enum = 0
        pos = pos + 4
        if (ebit == 0): 
          if ( str(eid) in IPFIX_DEF ):
            wkd = IPFIX_DEF[str(eid)]; wkd.update({"len":elen})
            doc.update({"format" + str(i).zfill(3) : IPFIX_DEF[str(eid)]["key"] + "(" + str(elen) + ")" })
            wktp["format"].append(wkd);
          else:
            doc.update({"format" + str(i).zfill(3) : "UNKNOWN(" + str(eid) + ")" + "(" + str(elen) + ")" })
            wktp["format"].append({"key":"UNKNOWN"  + str(eid) + ")","type":"N/A","len":elen});
        else: # ebit=1
          enum = struct.unpack('>L', message[pos:pos+4])
          pos = pos + 4
          wktp["format"].append({"key":"ENTERPRISE("  + str(eid) + ")","type":"N/A","len":elen});

        wktp["len"] = wktp["len"] + int(elen);

      dtp[sa][did][tid] = wktp  

      if ( elaflg ):
        res=es.index(index='flow_data4', document=doc)
      if ( dump ):
        pp.pprint (doc)
         
    # option template  
    elif (sid == 3 ):
      rh = struct.unpack('>HHH', message[20:26])
      tid = rh[0]
      fn  = rh[1]
      sfn = rh[2]
      if not ( tid in otp[sa][did] ): otp[sa][did][tid] = []

      wktp = {};
      wktp["exporttime"] = etime;
      wktp["len"]        = 0
      wktp["count"]      = fn; # fn include sfn
      wktp["scount"]     = sfn;
      wktp["format"]     = []

      doc = doccommon;
      doc.update({"type": "Option Template", "templateid": tid, "count": fn, "scount": sfn});

      i = 0
      pos = 26
      for i in range(fn):   # Field Count
        E = struct.unpack('>HH', message[pos:(pos+4)])
        ebit = int(bin((E[0] >> 15) & 0b1),0)
        eid  = int(bin((E[0] ) & 0b0111111111111111),0)
        elen = E[1]
        enum = 0
        pos = pos + 4
        if (ebit == 0):
          if ( str(eid) in IPFIX_DEF ):
            wkd = IPFIX_DEF[str(eid)]; wkd.update({"len":elen})
            doc.update({"format" + str(i).zfill(3) : IPFIX_DEF[str(eid)]["key"] + "(" + str(elen) + ")" })
            wktp["format"].append(wkd);
          else:
            doc.update({"format" + str(i).zfill(3) : "UNKNOWN(" + str(eid) + ")" + "(" + str(elen) + ")" })
            wktp["format"].append({"key":"UNKNOWN("  + str(eid) + ")", "type":"N/A","len":elen});
        else:        # ebit = 1
          enum = struct.unpack('>L', message[pos:pos+4])
          pos = pos + 4
          doc.update({"format" + str(i).zfill(3) : "ENTERPRISE("  + str(eid) + ")" + "(" + str(elen) + ")" })
          wktp["format"].append({"key":"ENTERPRISE("  + str(eid) + ")","type":"N/A","len":elen});
        
        wktp["len"] = wktp["len"] + int(elen);

      if ( wktp["len"] % 4 != 0 ):
        wktp["len"] = wktp["len"] + ( 4 - wktp["len"] % 4 )

      otp[sa][did][tid] = wktp  

      if ( elaflg ):
        res=es.index(index='flow_data4', document=doc)
      if ( dump ):
        pp.pprint (doc)
    
    else: # Flow Data
      pos = 20
      if (sid in dtp[sa][did]):
        if ( (slen - 4) % dtp[sa][did][sid]["len"] == 0 ):
          for j in range(int((slen - 4) / dtp[sa][did][sid]["len"])):
            d = {}
            doc = doccommon
            doc.update({"type": "Flow Data",})
            
            for i in dtp[sa][did][sid]["format"] : 
              if (i["type"] == "int"):
                doc[i["key"]] = getint(i["len"],pos);
              elif ( i["type"] == "ipv6Address"):
                doc[""+i["key"]] = getipv6(i["len"],pos);
              elif ( i["type"] == "dateTimeMilliseconds"):
                doc[i["key"]] = getint(i["len"],pos);
                doc[i["key"] + "_str" ] = getdatefrommilli(doc[i["key"]])
              else:
                doc.update({ i["key"]: "unsupported type(" + i["type"] + ")" })
              pos = pos + i["len"]
           
            # pps/bps
            pc = 0; bc = 0;
            #if (( op[sa][did]["samplingInterval"] > 0) and ( op[sa][did]["flowActiveTimeout"] > 0)):
            if ( op[sa][did]["samplingInterval"] > 0):
              pc = doc["packetDeltaCount"] * op[sa][did]["samplingInterval"]
              bc = doc["octetDeltaCount"] * 8 * op[sa][did]["samplingInterval"]

              if ("destinationIPv6Address" in doc):
                json_body = [
                   {
                     "measurement" : "v6",
                     "tags" : {
                       "host"   : sa,
                       "bgpSourceAsNumber"      : doc["bgpSourceAsNumber"],
                       "bgpDestinationAsNumber" : doc["bgpDestinationAsNumber"], 
                       "sourceIPv6Address"      : doc["sourceIPv6Address"],
                       "destinationIPv6Address" : doc["destinationIPv6Address"],
                       "ingressInterface"       : doc["ingressInterface"],
                       "egressInterface"        : doc["egressInterface"],
                     },
                     "time" : doc["flowEndMilliseconds"] * 1000000,
                     "fields" : {
                       "packets" : pc,
                       "octets"  : bc ,
                     }
                   }
                ]
                if ( idbflg ):
                  idb.write_points(json_body)

              doc["packets"] = pc; doc["octets"] = bc;
              if ( elaflg ):
                res=es.index(index='flow_data4', document=doc)
              if ( dump ):
                pp.pprint (doc)
            
      elif (sid in otp[sa][did]):   # Option data
        doc = doccommon
        doc.update({"type"   : "Option Data",})
        if ( (slen - 4) % otp[sa][did][sid]["len"] == 0 ):
          for i in otp[sa][did][sid]["format"] : 
            if (i["type"] == "int"):
              op[sa][did][i["key"]] = doc[i["key"]] = getint(i["len"],pos)
              #doc.update({ i["key"]: getint(i["len"],pos) })
            elif ( i["type"] == "ipv6Address"):
              op[sa][did][i["key"]] = doc[i["key"]] = getipv6(i["len"],pos)
              #doc.update({ i["key"]: getipv6(i["len"],pos) })
            elif ( i["type"] == "ipv4Address"):
              op[sa][did][i["key"]] = doc[i["key"]] = getipv4(i["len"],pos)
              #doc.update({ i["key"]: getipv4(i["len"],pos) })
            elif ( i["type"] == "dateTimeMilliseconds"):
              op[sa][did][i["key"]] = doc[i["key"]] = getint(i["len"],pos);
              op[sa][did][i["key"] + "_str"] = doc[i["key"] + "_str" ] = getdatefrommilli(doc[i["key"]])
            else:
              doc.update({ i["key"] : "unsupported type(" + i["type"] + ")" })
            pos = pos + i["len"]

          if ( elaflg ):
            res=es.index(index='flow_data4', document=doc)
          if ( dump ):
            pp.pprint (doc)

      #else:
      #  print("template not found")
      
  except KeyboardInterrupt:
    sock.close()
    break
