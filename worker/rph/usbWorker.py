# Modular Python Bitcoin Miner - rph USB
# Copyright (C) 2011-2012 Michael Sparmann (TheSeven)
# Copyright (C) 2011-2012 rphlx <rph@l0x.org>
#
#     This program is free software; you can redistribute it and/or
#     modify it under the terms of the GNU General Public License
#     as published by the Free Software Foundation; either version 2
#     of the License, or (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program; if not, write to the Free Software
#     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Please consider donating to 1PLAPWDejJPJnY2ppYCgtw5ko8G5Q4hPzh if you
# want to support further development of the Modular Python Bitcoin Miner.

###################################################
# rph usb worker interface module                 #
# https://bitcointalk.org/index.php?topic=44891.0 #
###################################################

import common
import usb
import array
import binascii
import threading
import time
import struct

class usbWorker(object):
  def __init__(self, miner, dict):
    self.__dict__ = dict
    self.miner = miner
    self.children = []
    self.uid = getattr(self, "uid", "")
    self.idx = getattr(self, "idx", 0)
    self.name = getattr(self, "name", "rph" + str(self.idx))
    self.jobinterval = getattr(self, "jobinterval", 30)
    self.jobspersecond = 1. / self.jobinterval  # Used by work buffering algorithm
    self.mhps = 0
    self.mhashes = 0
    self.jobsaccepted = 0
    self.accepted = 0
    self.rejected = 0
    self.invalid = 0
    self.starttime = time.time()
    self.statlock = threading.RLock()
    self.mainthread = threading.Thread(None, self.main, self.name + "_main")
    self.mainthread.daemon = True
    self.mainthread.start()

  # Report statistics about this worker module and its (non-existant) children.
  def getstatistics(self, childstats):
    # Acquire the statistics lock to stop statistics from changing while we deal with them
    with self.statlock:
      # Calculate statistics
      statistics = { \
        "name": self.name, \
        "children": childstats, \
        "mhashes": self.mhashes, \
        "mhps": self.mhps, \
        "jobsaccepted": self.jobsaccepted, \
        "accepted": self.accepted, \
        "rejected": self.rejected, \
        "invalid": self.invalid, \
        "starttime": self.starttime, \
        "currentpool": self.job.pool.name if self.job != None and self.job.pool != None else None, \
      }
    # Return result
    return statistics

  def cancel(self, blockchain):
    if self.job != None and self.job.pool != None and self.job.pool.blockchain == blockchain:
      self.canceled = True

  def find_dev(self):
    dev = usb.core.find(idVendor=0xf1f0, find_all=True)
    for d in dev:
      try:
        uid = d.ctrl_transfer(0xc0, 0x96, 0, 0, 16, 5000)
      except:
        # fallback for old firmware revisions that don't implement uid.
        uid = binascii.unhexlify("00000000000000000000000000000000")
        pass
      uid = binascii.hexlify(uid)
      #self.miner.log("got uid : " + uid + "\n", "")
      #self.miner.log("want uid: " + self.uid + "\n", "")
      if self.uid == "" or self.uid == uid: 
        self.dev = d
        return
    raise Exception("unable to find miner")

  def main(self):
    while True:
      try:
        self.error = None
        self.job = None
        self.checksuccess = False
        self.cancelled = False
        self.find_dev()
        # I'm too sexy for this job. Too sexy for this job. Too sexy:
        #job = common.Job(None, binascii.unhexlify("1625cbf1a5bc6ba648d1218441389e00a9dc79768a2fc6f2b79c70cf576febd0"), "\0" * 64 + binascii.unhexlify("4c0afa494de837d81a269421"), binascii.unhexlify("7bc2b302"))
        job = common.Job(self.miner, None, None, binascii.unhexlify("0d840c5cc3def3dfdb1dfaf01da77e451c2e786d15fe0876836a6999a4f0fc79"), "\0" * 64 + binascii.unhexlify("12f2f7f34f027f0c1a0e76ba"), None, binascii.unhexlify("d0c984a9"))
        self.sendjob(job)
        self.polljob()
        if self.error != None: raise self.error
        if not self.checksuccess: raise Exception("Timeout waiting for validation job to finish")
        self.miner.log(self.name + ": Running at %f MH/s\n" % self.mhps, "B")
        interval = min(30, 2**32 / 1000000. / self.mhps)
        self.jobinterval = min(self.jobinterval, max(0.5, interval * 0.9))
        self.miner.log(self.name + ": Job interval: %f seconds\n" % self.jobinterval, "B")
        self.jobspersecond = 1. / self.jobinterval
        self.miner.updatehashrate(self)
        while True:
          self.canceled = False
          job = self.miner.getjob(self)
          self.jobsaccepted = self.jobsaccepted + 1
          if self.canceled == True:
            if job.longpollepoch != job.pool.blockchain.longpollepoch: continue
            self.canceled = False;
          if self.error != None: raise self.error
          self.sendjob(job)
          self.polljob()
          if self.error != None: raise self.error
      except Exception as e:
        self.miner.log(self.name + ": %s\n" % e, "rB")
        self.error = e
        time.sleep(1)

  # poll USB MCU, ~1000 times per second, checking for nonce data,
  # a job timeout, or long poll cancellation
  def polljob(self):
    try:
      done = False
      a = array.array('B')
      while True:
        if self.error != None: break
        if self.cancelled: break
        # ignore pipe errors. (bug in pyusb? they never happen with the C implementation..)
        try:
            data = self.dev.ctrl_transfer(0xc0, 0x41, 0, 0, 1, 5000)
            if len(data):
              a = a + data
        except:
            time.sleep(0.01)
            pass
        now = time.time()
        if len(a) >= 4:
          golden = a[0:4]
          golden = golden[::-1]
          golden = golden.tostring()
          self.job.endtime = now
          self.job.sendresult(golden, self)
          delta = (now - self.job.starttime)
          self.mhps = struct.unpack("<I", golden)[0] / 1000000. / delta
          self.miner.updatehashrate(self) 
          if self.job.check != None:
            if self.job.check != golden:
              #raise Exception("Mining device is not working correctly (returned %s instead of %s)" % (binascii.hexlify(golden), binascii.hexlify(self.job.check)))
              self.miner.log("Mining device is not working correctly (returned %s instead of %s)" % (binascii.hexlify(golden), binascii.hexlify(self.job.check)))
            else:
              self.checksuccess = True
          done = True
        if done or (now - self.job.starttime) >= self.jobinterval:
            # TODO: adjust for communication delays.
            if self.job != None and self.job.pool != None:
                mhashes = (now - self.job.starttime) * self.mhps
                self.job.finish(mhashes, self)
            break
    except Exception as e:
      self.error = e

  def sendjob(self, job):
    cmd = binascii.unhexlify("40")
    self.dev.ctrl_transfer(0x40, 0x40, 0, 0, cmd + job.state[::-1] + job.data[75:63:-1], 5000)
    self.job = job
    self.job.starttime = time.time()
    # drain any leftover golden chars from the old job.
    time.sleep(0.01)
    try:
        while True:
            data = self.dev.ctrl_transfer(0xc0, 0x41, 0, 0, 1, 5000)
            if len(data) <= 0:
                break
    except:
        time.sleep(0.01)
        pass
