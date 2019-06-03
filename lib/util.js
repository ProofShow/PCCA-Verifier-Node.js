'use strict';

/**
 *  Convert a node buffer to ArrayBuffer
 *  @param {Object} nodeBuffer the node buffer
 *  @return {Object} the ArrayBuffer
 */
function _toArrayBuffer(nodeBuffer) {
  var arrayBuffer = new ArrayBuffer(nodeBuffer.length);
  var res = new Uint8Array(arrayBuffer);
  for (var i = 0; i < nodeBuffer.length; ++i) {
    res[i] = nodeBuffer[i];
  }
  return arrayBuffer;
}

module.exports.toArrayBuffer = _toArrayBuffer;
