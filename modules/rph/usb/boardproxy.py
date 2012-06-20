# Modular Python Bitcoin Miner
# Copyright (C) 2012 Michael Sparmann (TheSeven)
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



###############################################################
# rph usb out of process board access dispatcher              #
###############################################################



import time
import signal
import struct
import traceback
from threading import Thread, Condition, RLock
from multiprocessing import Process
from core.job import Job
from .driver import rphUSBDevice


class rphUSBBoardProxy(Process):
  

  def __init__(self, rxconn, txconn, serial, takeover, firmware, pollinterval):
    super(rphUSBBoardProxy, self).__init__()
    self.rxconn = rxconn
    self.txconn = txconn
    self.serial = serial
    self.takeover = takeover
    self.firmware = firmware
    self.pollinterval = pollinterval


  def run(self):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    self.lock = RLock()
    self.wakeup = Condition()
    self.error = None
    self.pollingthread = None
    self.shutdown = False
    self.job = None
    self.checklockout = 0
    self.lastnonce = 0
    self.multiplier = 0
  
    try:

      # Listen for setup commands
      while True:
        data = self.rxconn.recv()
        
        if data[0] == "connect": break
        
        else: raise Exception("Unknown setup message: %s" % str(data))
        
      # Connect to board and upload firmware if neccessary
      self.device = rphUSBDevice(self, self.serial, self.takeover, self.firmware)
      
      # Configure clock
      #self._set_multiplier(192000000)
      self.send("speed_changed", 16*192000000)

      # Start polling thread
      self.pollingthread = Thread(None, self.polling_thread, "polling_thread")
      self.pollingthread.daemon = True
      self.pollingthread.start()
      
      self.send("started_up")

      # Listen for commands
      while True:
        if self.error: raise self.error
      
        data = self.rxconn.recv()
        
        if data[0] == "shutdown": break

        elif data[0] == "ping": self.send("pong")

        elif data[0] == "pong": pass

        elif data[0] == "set_pollinterval":
          self.pollinterval = data[1]
          with self.wakeup: self.wakeup.notify()
        
        elif data[0] == "send_job":
          self.checklockout = time.time() + 1
          self.job = data[1]
          with self.wakeup:
            start = time.time()
            self.device.send_job(data[2][::-1] + data[1][75:63:-1])
            end = time.time()
            self.lastnonce = 0
          self.checklockout = end + 0.5
          self.respond(start, end)
        
        else: raise Exception("Unknown message: %s" % str(data))
      
    except: self.log("Exception caught: %s" % traceback.format_exc(), 100, "r")
    finally:
      self.shutdown = True
      with self.wakeup: self.wakeup.notify()
      try: self.pollingthread.join(2)
      except: pass
      self.send("dying")
      
      
  def send(self, *args):
    with self.lock: self.txconn.send(args)
      
      
  def respond(self, *args):
    self.send("response", *args)
      
      
  def log(self, message, loglevel, format = ""):
    self.send("log", message, loglevel, format)
    
    
  def polling_thread(self):
    try:
      lastshares = []
      counter = 0

      while not self.shutdown:
        # Poll for nonces
        now = time.time()
        nonces = self.device.read_nonces()
        exhausted = False
        with self.wakeup:
          if len(nonces) > 0 and nonces[0] < self.lastnonce:
            self.lastnonce = nonces[0]
            exhausted = True
        if exhausted: self.send("keyspace_exhausted")
        for nonce in nonces:
          if not nonce[0] in lastshares:
           if self.job: self.send("nonce_found", time.time(), struct.pack("<I", nonce[0]))
           lastshares.append(nonce[0])
           while len(lastshares) > len(nonces): lastshares.pop(0)

        counter += 1
        if counter >= 10:
          counter = 0
          # Read temperatures
          temp = self.device.read_temps()
          self.send("temperature_read", temp)

        with self.wakeup: self.wakeup.wait(self.pollinterval)
        
    except Exception as e:
      self.log("Exception caught: %s" % traceback.format_exc(), 100, "r")
      self.error = e
      # Unblock main thread
      self.send("ping")

      
  def _set_multiplier(self, multiplier):
    multiplier = min(max(multiplier, 1), self.device.maximum_multiplier)
    if multiplier == self.multiplier: return
    self.device.set_multiplier(multiplier)
    self.multiplier = multiplier
    self.checklockout = time.time() + 2
    self.send("speed_changed", (multiplier + 1) * self.device.base_frequency * self.device.hashes_per_clock)
