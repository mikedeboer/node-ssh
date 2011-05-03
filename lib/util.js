//https://github.com/sjwalter/Node-Packer.git
function pack(format) {
    var argIndex = 1;
    var args = arguments;

    if(args[1] instanceof Array) {
        // We were passed an array of data to pack
        args = arguments[1];
        argIndex = 0;
    }

    // Because node Buffers can't be resized, we store the result
    // as an array of Buffers and keep track of the total length,
    // then return a new buffer from this array at the end.
    var result = [];
    var totalLength = 0;

    // TODO: Byte order first-char
    // For now, we're assuming '!' (Network--big-endian). This is
    // different from python's struct.pack assumption that the
    // default is @ (native size and byte order).
    var formatIndex = 0;

    switch(format[0]) {
        case "@":
        case "=":
        case "<":
        case ">":
        case "!":
            // Don't do anything with these right now, and maybe
            // I can't (can I manipulate the byte-orderings?)
            // Just keeping this here to ensure compatibility
            // with python's struct.pack, which I'm only doing
            // so that I have to write less documentation.
            formatIndex = 1;
            break;
    }

    for(; formatIndex < format.length; formatIndex++) {
        var curType = format[formatIndex];
        var curAddition;
        switch(curType) {
            case "x":
                // Pad byte, just one empty byte.
                var tmp = new Buffer(1);
                tmp[0] = 0;
                result.push(tmp);
                totalLength += 1;
                break;
            case "c":
            case "b":
            case "B":
                // Character, one byte.
                var tmp = new Buffer(1);
                var character = args[argIndex];
                if(typeof character != "number") {
                    character = parseInt(character);
                }
                if(character > 255) {
                    throw new Error("Can not pack a B-type from an int > 255");
                }
                tmp[0] = character;
                result.push(tmp);
                totalLength += 1;
                break;
            case "I":
            case "L":
                // unsigned integer/long, 4 bytes
                var tmp = new Buffer(4);
                var num = args[argIndex];
                if(typeof num != "number") {
                    num = parseInt(num);
                }
                tmp[0] = num & 255;
                tmp[1] = num >> 8 & 255;
                tmp[2] = num >> 16 & 255;
                tmp[3] = num >> 24 & 255;
                result.push(tmp);
                totalLength += 4;
                break;
            default:
                throw new Error("Unsupported packing type: " + curType);
                break;
        }
        argIndex += 1;
    }

    // Prepare the actual return buffer
    var ret = new Buffer(totalLength);
    var retIndex = 0;
    for(var i = 0; i < result.length; i++) {
        var curResult = result[i];
        for(var j = 0; j < curResult.length; j++) {
            ret[retIndex] = curResult[j];
            retIndex += 1;
        }
    }
    return ret;
}

function unpack(format, buffer) {
    if(!(buffer instanceof Buffer)) {
        throw new Error("unpack expects a second argument of type Buffer");
    }

    var formatIndex = 0;
    var bufferIndex = 0;
    var result = new Array();

    switch(format[0]) {
        case "@":
        case "=":
        case ">":
        case "<":
        case "!":
            formatIndex = 1;
            break;
    }

    for(; formatIndex < format.length; formatIndex++) {
        var curType = format[formatIndex];

        switch(curType) {
            case "x":
                // Just a pad byte. Next!
                bufferIndex += 1;
                break;
            case "c":
            case "b":
            case "B":
                result.push(parseInt(buffer[bufferIndex]));
                bufferIndex += 1;
                break;
            case "I":
            case "L":
                var num = 
                    parseInt((buffer[bufferIndex + 3] & 255) << 24) +
                    parseInt((buffer[bufferIndex + 2] & 255) << 16) +
                    parseInt((buffer[bufferIndex + 1] & 255) << 8) +
                    parseInt(buffer[bufferIndex] & 255);
                result.push(num);
                bufferIndex += 4;
                break;
            default:
                throw new Error("Unsupported format type: " + curType);
                break;
        }
    }
    return result;
}

module.exports.pack = pack;
module.exports.unpack = unpack;

var Buffy = function() {
  this._store = new Array();
  this._length = 0;
};
Buffy.prototype.append = function(buffer) {
  this._length += buffer.length;
  this._store.push(buffer);
};
Buffy.prototype.indexOf = function(bytes, start) {
  if (start && (start < 0 || start >= this._length))
    return -1;//throw new Error('OOB');
  if (typeof bytes === 'number')
    bytes = [bytes];
  start = start || 0;
  var ret = -1, matching = false, foundStart = false, bn = 0, bc = 0, matchedAt,
      numbufs = this._store.length, buflen, bytesPos = 0,
      lastBytesPos = bytes.length-1, i;
  while (bn < numbufs) {
    i = 0;
    buflen = this._store[bn].length;
    if (!foundStart) {
      if (start >= buflen)
        start -= buflen;
      else {
        i = start;
        foundStart = true;
      }
    }
    if (foundStart) {
      for (; i<buflen; ++i) {
        if (this._store[bn][i] === bytes[bytesPos]) {
          if (bytesPos === 0) {
            matchedAt = bc + i;
          }
          if (bytesPos === lastBytesPos) {
            ret = matchedAt;
            break;
          }
          matching = true;
          ++bytesPos;
        } else if (matching) {
          matching = false;
          bytesPos = 0;
          --i; // retry current byte with reset bytesPos
        }
      }
      if (ret > -1)
        break;
    }
    bc += buflen;
    ++bn;
  }
  return ret;
};
Buffy.prototype.GCBefore = function(index) {
  if (index < 0 || index > this._length)
    throw new Error('OOB');
  var toRemove = 0, amount = 0;
  for (var bn=0,i=0,len=this._store.length; bn<len; ++bn) {
    if (bn > 0) {
      amount += this._store[bn-1].length;
      this._length -= this._store[bn-1].length;
      ++toRemove;
    }
    i += this._store[bn].length;
    if (index < i)
      break;
  }
  if (toRemove > 0)
    this._store.splice(0, toRemove);
  return amount;
};
Buffy.prototype.copy = function(destBuffer, destStart, srcStart, srcEnd) {
  if (typeof srcEnd === 'undefined')
    srcEnd = this._length;
  destStart = destStart || 0;
  srcStart = srcStart || 0;
  if (srcStart < 0 || srcStart > this._length || srcEnd > this._length
      || srcStart > srcEnd || destStart + (srcEnd-srcStart) > destBuffer.length)
    throw new Error('OOB');
  if (srcStart !== srcEnd) {
    var foundStart = false, totalBytes = (srcEnd-srcStart),
        buflen, destPos = destStart;
    for (var bn=0,len=this._store.length; bn<len; ++bn) {
      buflen = this._store[bn].length;
      if (!foundStart) {
        if (srcStart >= buflen)
          srcStart -= buflen;
        else
          foundStart = true;
      }
      if (foundStart) {
        if ((totalBytes - destPos) <= (buflen - srcStart)) {
          this._store[bn].copy(destBuffer, destPos, srcStart, srcStart + (totalBytes - destPos));
          break;
        } else {
          this._store[bn].copy(destBuffer, destPos, srcStart, buflen);
          destPos += (buflen - srcStart);
          srcStart = 0;
        }
      }
    }
  }
};
Buffy.prototype.splice = function(index, howmany, el) {
  var idxLastDel = index + howmany, idxLastAdd = index,
      numNew = 0, newEls, idxRet = 0;
  if (index < 0 || index >= this._length || howmany < 0 || idxLastDel >= this._length)
    throw new Error('OOB');
  if (el) {
    newEls = Array.prototype.slice.call(arguments).slice(2);
    numNew = newEls.length;
    idxLastAdd = index + numNew;
  }
  var idxLastMin = Math.min(idxLastAdd, idxLastDel),
      idxLastMax = Math.max(idxLastAdd, idxLastDel);
  var ret = new Array(howmany);
  if (numNew === howmany) {
    for (var bn=0,i=0,blen,start=-1,len=this._store.length; bn<len; ++bn) {
      blen = this._store[bn].length;
      if (start < 0) {
        i += blen;
        if (index < i)
          start = blen-(i-index);
      } else {
        for (var j=start; j<blen; ++j,++index) {
          if (index === idxLastAdd)
            return ret;
          ret[idxRet] = this._store[bn][j];
          this._store[bn][j] = newEls[idxRet++];
        }
        start = 0;
      }
    }
  } else {
    
  }
  return ret;
};
Buffy.prototype.__defineGetter__('length', function() {
  return this._length;
});
Buffy.prototype.get = function(index) {
  var ret = false;
  if (index >= 0 && index < this._length) {
    for (var bn=0,i=0,blen,len=this._store.length; bn<len; ++bn) {
      blen = this._store[bn].length
      i += blen;
      if (index < i) {
        ret = this._store[bn][blen-(i-index)];
        break;
      }
    }
  }
  return ret;
};
Buffy.prototype.set = function(index, value) {
  var ret = false;
  if (index >= 0 && index < this._length && typeof value === 'number'
      && value >= 0 && value <= 255) {
    for (var bn=0,i=0,blen,len=this._store.length; bn<len; ++bn) {
      blen = this._store[bn].length
      i += blen;
      if (index < i) {
        this._store[bn][blen-(i-index)] = value;
        ret = true;
        break;
      }
    }
  }
  return ret;
};
Buffy.prototype.toString = function(encoding, start, end) {
  var ret = new Array();
  if (typeof end === 'undefined')
    end = this._length;
  start = start || 0;
  if (start < 0 || start > this._length || end > this._length || start > end)
    throw new Error('OOB');
  if (start !== end) {
    if (start === 0 && end === this._length) {
      // simple case
      for (var i=0,len=this._store.length; i<len; ++i)
        ret.push(this._store[i].toString(encoding));
    } else {
      var foundStart = false, totalBytes = (end-start),
          buflen, destPos = 0;
      for (var bn=0,len=this._store.length; bn<len; ++bn) {
        buflen = this._store[bn].length;
        if (!foundStart) {
          if (start >= buflen)
            start -= buflen;
          else
            foundStart = true;
        }
        if (foundStart) {
          if ((totalBytes - destPos) <= (buflen - start)) {
            ret.push(this._store[bn].toString(encoding, start, start + (totalBytes - destPos)));
            break;
          } else {
            ret.push(this._store[bn].toString(encoding, start, buflen));
            destPos += (buflen - start);
            start = 0;
          }
        }
      }
    }
  }
  return ret.join('');
};
Buffy.prototype.inspect = function() {
  var len = this._store.length, ret = '<Buffy' + (len === 0 ? ' ' : '');
  for (var i=0,tmp,len=this._store.length; i<len; ++i) {
    tmp = this._store[i].inspect();
    ret += ' ' + tmp.substring(7, tmp.length-1).trim();
  }
  ret += '>';
  return ret;
};

module.exports.Buffy = Buffy;

function concat(bufs) {
    var buffer, length = 0, index = 0;
    
    if (!Array.isArray(bufs)) {
        bufs = Array.prototype.slice.call(arguments);
    }
    for (var i=0, l=bufs.length; i<l; i++) {
        buffer = bufs[i];
        if (!Buffer.isBuffer(buffer)) {
            buffer = bufs[i] = new Buffer(buffer);
        }
        length += buffer.length;
    }
    buffer = new Buffer(length);
    
    bufs.forEach(function (buf, i) {
        buf = bufs[i];
        buf.copy(buffer, index, 0, buf.length);
        index += buf.length;
        delete bufs[i];
    });
    
    return buffer;
}
Buffer.concat = concat;

Buffer.prototype.__addchunk_index = 0;

Buffer.prototype.addChunk = function (chunk) {
    var  len = Math.min(chunk.length, this.length - this.__addchunk_index);
    
    if (this.__addchunk_index === this.length) {
        //throw new Error("Buffer is full");
        return false;
    }
    
    chunk.copy(this, this.__addchunk_index, 0, len);
    
    this.__addchunk_index += len;
    
    if (len < chunk.length) {
        //remnant = new Buffer(chunk.length - len);
        //chunk.copy(remnant, 0, len, chunk.length);
        // return remnant;
        return chunk.slice(len, chunk.length);
    }
    
    if (this.__addchunk_index === this.length) {
        return true;
    }
};
