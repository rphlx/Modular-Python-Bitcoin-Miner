# Modular Python Bitcoin Miner
# Copyright (C) 2012 Michael Sparmann (TheSeven)
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



#########################################
# rph usb level driver                  #
#########################################



import time
import usb
import struct
import traceback
from array import array
from threading import RLock
from binascii import hexlify, unhexlify



class rphUSBDevice(object):
  

  def __init__(self, proxy, serial, takeover, firmware):
    self.lock = RLock()
    self.proxy = proxy
    self.serial = serial
    self.takeover = takeover
    self.firmware = firmware
    self.handle = None
    self.rxdata = array("B")
    permissionproblem = False
    deviceinuse = False
    for bus in usb.busses():
      if self.handle != None: break
      for dev in bus.devices:
        if self.handle != None: break
        if dev.idVendor == 0xf1f0:
          try:
            handle = dev.open()
            _serial = hexlify(handle.controlMsg(0xc0, 0x96, 16, 0, 0, 100))
            #_serial = "0" # handle.getString(dev.iSerialNumber, 100).decode("latin1")
            if serial == "" or serial == _serial:
              try:
                if self.takeover:
                  handle.reset()
                  time.sleep(1)
                configuration = dev.configurations[0]
                interface = configuration.interfaces[0][0]
                handle.setConfiguration(configuration.value)
                handle.claimInterface(interface.interfaceNumber)
                handle.setAltInterface(interface.alternateSetting)
                self.handle = handle
                self.serial = _serial
              except: deviceinuse = True
          except: permissionproblem = True
    if self.handle == None:
      if deviceinuse:
        raise Exception("Can not open the specified device, possibly because it is already in use")
      if permissionproblem:
        raise Exception("Can not open the specified device, possibly due to insufficient permissions")
      raise Exception("Can not open the specified device")

  
  def set_multiplier(self, multiplier):
    return None
    #with self.lock:
    #  self.handle.controlMsg(0x40, 0x83, b"", multiplier, 0, 100)
      
  
  def send_job(self, data):
    with self.lock:
      self.handle.controlMsg(0x40, 0x40, unhexlify("40") + data, 0, 0, 100)
      
  
  def read_nonces(self):
    with self.lock:
      char = ''
      try:
        char = self.handle.controlMsg(0xc0, 0x41, 1, 0, 0, 100)
      except:
        time.sleep(0.01)
        pass
      if len(char):
          self.rxdata = self.rxdata + char
    nonces = []
    if len(self.rxdata) >= 4:
        golden = self.rxdata[0:4]
        golden = golden[::-1]
        golden = golden.tostring()
        nonces.append(struct.unpack("<I", golden))
        self.rxdata = array("B")
#    for i in range(self.num_nonces):
#      values = struct.unpack("<III", data[12 * i : 12 * (i + 1)])
#      nonces.append((values[0] - self.nonce_offset, values[1] - self.nonce_offset, values[2]))
    return nonces
      
