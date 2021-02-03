/* Copyright (c) 2020 Daniel Radtke. See the file LICENSE for copying permission. */
/* Copyright (c) 2018 Andreas Dröscher. See the file LICENSE for copying permission. */
/* Copyright (c) 2013 Gordon Williams, Pur3 Ltd

------------------------------------------------------------------------------

All sections of code within this repository are licensed under an MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

var ntag = E.compiledC(`
// void setTagPointer(int)
// int getTagPointer()
// void setTagByte(int, int)
// int getTagByte(int)
// void setResponsePointer(int)
// void setAuthenticated(bool)
// bool getAuthenticated()
// void setBackdoor(bool)
// bool getBackdoor()
// void setTagWritten()
// bool getTagWritten()
// bool fixUid()
// int processRx(int, int)

unsigned char *tag;
void setTagPointer(unsigned char *pointer){
  tag = pointer;
}

int getTagPointer(){
  return (int)tag;
}

void setTagByte(int offset, unsigned char value){
  tag[offset] = value;
}

unsigned char getTagByte(int offset){
  return tag[offset];
}

unsigned char *tx;
void setResponsePointer(unsigned char *pointer){
  tx = pointer;
}

bool authenticated = false;
void setAuthenticated(bool value){ authenticated = value; }
bool getAuthenticated(){ return authenticated; }

bool backdoor = false;
void setBackdoor(bool value){ backdoor = value; }
bool getBackdoor() { return backdoor; }

bool tagWritten = false;
void setTagWritten(bool value){ tagWritten = value; }
bool getTagWritten(){ return tagWritten; }

bool fixUid(){
  unsigned char bcc0 = tag[0] ^ tag[1] ^ tag[2] ^ 0x88;
  unsigned char bcc1 = tag[4] ^ tag[5] ^ tag[6] ^ tag[7];

  if (tag[3] != bcc0 || tag[8] != bcc1){
    tag[3] = bcc0;
    tag[8] = bcc1;

    return true;
  }

  return false;
}

bool isLocked(int page){
  if (page == 0 || page == 1) return true;

  // Static Lock Bytes
  int bit;
  for (bit = 0; bit < 8; bit++){
    if (tag[11] & (1 << bit)){
      if ((bit + 8) == page){
        return true;
      }
    }

    if (tag[10] & (1 << bit)){
      switch (bit){
        case 0: //BL-CC
        case 1: //BL-9-4
        case 2: //BL-15-10
        case 3: //L-CC
          break;

        default: {
          if ((bit + 4) == page){
            return true;
          }
        } break;
      }
    }
  }

  if (!authenticated){
    if (tag[520] & 0b00000001 > 0 && (page >= 16 && page <= 31))
      return true;

    if (tag[520] & 0b00000010 > 0 && (page >= 32 && page <= 47))
      return true;

    if (tag[520] & 0b00000100 > 0 && (page >= 48 && page <= 63))
      return true;

    if (tag[520] & 0b00001000 > 0 && (page >= 64 && page <= 79))
      return true;

    if (tag[520] & 0b00010000 > 0 && (page >= 80 && page <= 95))
      return true;

    if (tag[520] & 0b00100000 > 0 && (page >= 96 && page <= 111))
      return true;

    if (tag[520] & 0b01000000 > 0 && (page >= 112 && page <= 127))
      return true;

    if (tag[520] & 0b10000000 > 0 && (page >= 128 && page <= 129))
      return true;
  }

  return false;
}

unsigned char *memcpy(unsigned char *dest_str, unsigned char *src_str, int number){
  int i;

  for (i = 0; i < number; i++)
    dest_str[i] = src_str[i];

  return dest_str;
}

int processRx(int rxLen, unsigned char *rx){
  if (rxLen == 0){
    tx[0] = 0;
    return -1;
  }

  switch (rx[0]) {
    case 0x30: { // Read
      if (rxLen < 2)
        return 0;

      unsigned char page = rx[1];

      if (backdoor == false && (page < 0 || page > 134)){
        tx[0] = 0x00;
        return -1;
      }

      if (!backdoor && (page == 133 || page == 134)){
        tx[0] = tx[1] = tx[2] = tx[3] = 0x00;
        return 4;
      }

      memcpy(tx, &tag[page * 4], 4);
      return 4;
    } break;

    case 0xA2: { // Write
      if (!backdoor && (rx[1] < 0 || rx[1] > 134 || isLocked(rx[1]))) {
        tx[0] = 0x00;
        return -1;
      }

      if (!backdoor) {
        if (rx[1] == 2) {
          tag[10] = tag[10] | rx[4];
          tag[11] = tag[11] | rx[5];
          tx[0] = 0x0A;

          return -1;
        }

        if (rx[1] == 3) {
          tag[16] = tag[16] | rx[2];
          tag[17] = tag[17] | rx[3];
          tag[18] = tag[18] | rx[4];
          tag[19] = tag[19] | rx[5];
          tx[0] = 0x0A;

          return -1;
        }

        if (rx[1] == 130) {
          // TODO: Dynamic lock bits
        }
      }

      int index = rx[1] * 4;

      if ((index > 568) || (!backdoor && index > 536)) {
        tx[0] = 0x00;
        return -1;
      } else {
        memcpy(&tag[index], &rx[2], 4);
        tx[0] = 0x0A;
        return -1;
      }
    } break;

    case 0x60: { // Version
      tx[0] = 0x00;
      tx[1] = 0x04;
      tx[2] = 0x04;
      tx[3] = 0x02;
      tx[4] = 0x01;
      tx[5] = 0x00;
      tx[6] = 0x11;
      tx[7] = 0x03;
      return 8;
    } break;

    case 0x3A: { // Fast Read
      if (rxLen < 3){
        tx[0] = 0x00;
        return -1;
      }

      if (rx[1] > rx[2] || rx[1] < 0 || rx[2] > 134) {
        tx[0] = 0x00;
        return -1;
      }

      int txLen = (rx[2] - rx[1] + 1) * 4;
      memcpy(tx, &tag[rx[1] * 4], txLen);
      return txLen;
    } break;

    case 0x1B: { // Password Auth
      authenticated = true;
      tx[0] = 0x80;
      tx[1] = 0x80;
      return 2;
    } break;

    case 0x3C: { // Read Signature
      memcpy(tx, &tag[540], 32);
      return 32;
    } break;

    case 0x88: { // CUSTOM: Restart NFC
      return -3;
    } break;

    case 0x1A: { // Auth
      return 0;
    } break;

    case 0x93: { // SEL_REQ CL1
      tx[0] = 0x04; // ISO14443A_UID0_CT
      tx[0] = 0xDA;
      tx[1] = 0x17;
      return 0;
    } break;

    default: { // Unknown command
      tx[0] = 0;
      return -2;
    } break;
  }

  return 0;
}
`);

function NFCTag() {
  this.setData();

  this.responseBuffer = new Uint8Array(572);
  var respAddr = E.getAddressOf(this.responseBuffer, true);
  if (!respAddr) throw new Error("Not a Flat String");
  ntag.setResponsePointer(respAddr);

  ntag.setAuthenticated(false);
  ntag.setBackdoor(false);
  ntag.setTagWritten(false);

  this.filename = "tag.bin";
  this.led = [LED1];

  var self = this;

  NRF.on('NFCon', function() {
    for (var i = 0; i<self.led.length; i++) {
      digitalWrite(self.led[i], 1);
    }
  });

  NRF.on('NFCoff', function() {
    for (var i = 0; i<self.led.length; i++) {
      digitalWrite(self.led[i], 0);
    }

    ntag.setAuthenticated(false);
    ntag.setBackdoor(false);

    if (ntag.getTagWritten() == true) {
      //console.log("Saving tag to flash");
      //require("Storage").write(filename, this._data);
      ntag.setTagWritten(false);
    }

    if (ntag.fixUid()) {
      console.log("Fixed tag UID");
      NRF.nfcStop();
      NRF.nfcStart(new Uint8Array([self._data[0], self._data[1], self._data[2], self._data[4], self._data[5], self._data[6], self._data[7]]));
    }
  });

  NRF.on('NFCrx', function(rx) {
    var rxAddr = E.getAddressOf(rx, true);
    if (!rxAddr) throw new Error("RX not a flat string");
    var txLen = ntag.processRx(rx.length, rxAddr);
    //console.log(rx);
    //console.log(txLen);

    if (txLen == 0) {
      NRF.nfcSend();
    } else if (txLen == -3) {
      // Custom command to restart NFC (0x88)
      self.setData();
    } else if (txLen == -2) {
      NRF.nfcSend();
      // unknown command, log it
      console.log("Unknown command: 0x" + rx[0].toString(16));
      console.log(rx);
    } else if (txLen == -1) {
      NRF.nfcSend(self.responseBuffer[0]);
    } else {
      NRF.nfcSend(self.responseBuffer.slice(0, txLen));
    }
  });
}

NFCTag.prototype = {
  setData: function setData(){
    //shutdown
    NRF.nfcStop();

    // Get the address and set the pointer
    var dataAddr = E.getAddressOf(tags[currentTag].buffer,true);
    if (!dataAddr) throw new Error("Not a Flat String");
    ntag.setTagPointer(dataAddr);

    //fix bcc0 and bcc1 if needed
    if (ntag.fixUid()){
      console.log("Fixed bad bcc");
    }

    this.data = tags[currentTag].buffer;

    var uid = new Uint8Array([tags[currentTag].buffer[0], tags[currentTag].buffer[1], tags[currentTag].buffer[2], tags[currentTag].buffer[4], tags[currentTag].buffer[5], tags[currentTag].buffer[6], tags[currentTag].buffer[7]]);

    console.log("Starting NFC");
    console.log(uid);

    //re-start
    var header = NRF.nfcStart();

  }
};

var tags = (function() {
  var storage = require("Storage");
  var data = [
    { led: [LED1] },
    { led: [LED1, LED2] },
    { led: [LED2] },
    { led: [LED2, LED3] },
    { led: [LED3] }
  ];

  for (var i = 0; i < data.length; i++) {
    data[i].filename = "tag" + i + ".bin";

    var buffer = storage.readArrayBuffer(data[i].filename);

    if (buffer) {
      var output = new Uint8Array(buffer.length);
      for (var buffPos = 0; buffPos < buffer.length; buffPos++) {
        output[buffPos] = buffer[buffPos];
      }

      data[i].buffer = output;
    } else {
      data[i].buffer = new Uint8Array(572);
    }
  }

  return data;
})();

var currentTag = 0;

var tag = new NFCTag();
tag.filename = tags[currentTag].filename;

setWatch(function() {
  NRF.nfcStop();
  currentTag++;

  if (currentTag > tags.length - 1) {
    currentTag = 0;
  }

  tag.led = tags[currentTag].led;

  LED1.write(0);
  LED2.write(0);
  LED3.write(0);

  for (var i = 0; i<tag.led.length; i++) {
    digitalWrite(tag.led[i], 1);
  }

  setTimeout(() => {
    for (var i = 0; i<tag.led.length; i++) {
      digitalWrite(tag.led[i], 0);
    }

    tag.led = tags[currentTag].led;
    tag.filename = tags[currentTag].filename;
    tag.setData(tags[currentTag].buffer);
  }, 200);
}, BTN, { repeat: true, edge:"rising", debounce:50 });
