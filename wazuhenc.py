#!/usr/bin/env python
# This is external node classifier to distribute integer ids for ossec agents
# There is possbility to add static host configuration via config file, via format:
#  <id>:<hostname>
#  15:host1
#  33:host2
# range: 1 - 14000

import cPickle as pickle
import zlib
import traceback
import os
import logging
import sys

MAX_OSSEC_CLIENTS = 14000

logger = logging.getLogger('wazuhenc')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler('/tmp/wazuhenc.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
# Disable logfile
#fh.setFormatter(formatter)
# add the handlers to logger
logger.addHandler(ch)
logger.addHandler(fh)

hdata = []

ppath='/var/lib/puppet/wazuhenc.dat'
cpath='/var/lib/puppet/wazuhenc.conf'

if len(sys.argv) < 2:
    logger.critical('Need a hostname as an argument')
    sys.exit(1)

nodename = sys.argv[1]

def cread():
  data = []
  try:
    with open(cpath, "a+") as f:
      f.seek(0)
      d=f.read().splitlines()
      if len(d) > 0:
        data = dict([i.split(':') for i in d if not i.startswith('#') and ':' in i])
      else:
        logger.warn('No config file found. Creating fresh one!')
        data = {}
  except Exception as e:
      print(traceback.format_exc(e))
  return data

def psave(data):
  try:
    with open(ppath, 'w+') as fp:
      fp.write(zlib.compress(pickle.dumps(data)))
  except Exception as e:
    print(traceback.format_exc(e))

def pread():
  data = []
  try:
    with open(ppath, "a+") as f:
      f.seek(0)
      d=f.read()
      if len(d) > 0:
        data = pickle.loads(zlib.decompress(d))
      else:
        logger.warn('No data file found. Creating fresh one!')
        data = []
  except Exception as e:
      print(traceback.format_exc(e))
  return data

def main():
  # Reserved host data configured via config file
  rdata = cread()
  # Dynamic host data assigned by this script running on puppetmaster
  hdata = pread()
  # Due to requirement to have static agent ids configured from config file we need to maintain full list of ids up to max allowed
  if len(hdata) == 0:
    [ hdata.insert(x, None) for x in range(MAX_OSSEC_CLIENTS) ]

  # Ossec cannot accept 0 as agent id so we start indexing from 1, ensure that
  hdata[0] = None

  hid = -1

  # consistency checks
  if MAX_OSSEC_CLIENTS+1 in rdata.keys():
    logger.critical('Reserved host id %s for host %s exceeds %s' % (MAX_OSSEC_CLIENTS+1, rdata[MAX_OSSEC_CLIENTS+1], MAX_OSSEC_CLIENTS))
    sys.exit(2)

  # Populate dynamic host data items with reserved hosts from config file
  # If for some reason data from config file overwrites dynamic data, after next puppet run, new unique agent id will be generated
  for (k,v) in rdata.items():
    k = int(k)
    if hdata[k] != v and k > 0:
      hdata[k] = v
  try:
    hid = hdata.index(nodename)
  except ValueError:
    if sum(1 for i in hdata if i != None) < MAX_OSSEC_CLIENTS:
      # Find next available empty space to insert new host (start from 1)
      ind = next( i for i,j in enumerate(hdata) if j == None and i > 0)
      hdata[ind] = nodename
      hid = ind
      psave(hdata)
    else:
      logger.critical('Maximum of ossec clients reached at: %s' % MAX_OSSEC_CLIENTS)
      sys.exit(2)
  except Exception as e:
    print(traceback.format_exc(e))

  print '---'
  print 'parameters:'
  print '  ossec_agent_id: \'%03d\'' %hid

if __name__ == "__main__":
    main()
