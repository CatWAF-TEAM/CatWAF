// Small dependency-free PNG renderer. Answers never appear as SVG text or metadata.
const crypto = require('crypto')
const zlib = require('zlib')

// Original 5x7 bitmap glyphs; each integer encodes one row.
const FONT = {
  A:[14,17,17,31,17,17,17], B:[30,17,17,30,17,17,30], C:[14,17,16,16,16,17,14],
  D:[30,17,17,17,17,17,30], E:[31,16,16,30,16,16,31], F:[31,16,16,30,16,16,16],
  G:[14,17,16,23,17,17,15], H:[17,17,17,31,17,17,17], J:[7,2,2,2,18,18,12],
  K:[17,18,20,24,20,18,17], L:[16,16,16,16,16,16,31], M:[17,27,21,21,17,17,17],
  N:[17,25,25,21,19,19,17], P:[30,17,17,30,16,16,16], Q:[14,17,17,17,21,18,13],
  R:[30,17,17,30,20,18,17], S:[15,16,16,14,1,1,30], T:[31,4,4,4,4,4,4],
  U:[17,17,17,17,17,17,14], V:[17,17,17,17,17,10,4], W:[17,17,17,21,21,27,17],
  X:[17,17,10,4,10,17,17], Y:[17,17,10,4,4,4,4], Z:[31,1,2,4,8,16,31],
  '2':[14,17,1,2,4,8,31], '3':[30,1,1,14,1,1,30], '4':[2,6,10,18,31,2,2],
  '5':[31,16,16,30,1,1,30], '6':[14,16,16,30,17,17,14], '7':[31,1,2,4,8,8,8],
  '8':[14,17,17,14,17,17,14], '9':[14,17,17,15,1,1,14],
}

const CRC = Array.from({ length: 256 }, (_, n) => {
  for (let k = 0; k < 8; k++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1
  return n >>> 0
})
function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type), data])
  let crc = 0xffffffff
  for (const b of body) crc = CRC[(crc ^ b) & 255] ^ (crc >>> 8)
  const out = Buffer.alloc(data.length + 12)
  out.writeUInt32BE(data.length, 0)
  body.copy(out, 4)
  out.writeUInt32BE((crc ^ 0xffffffff) >>> 0, out.length - 4)
  return out
}

function png(answer) {
  if (!/^[A-HJ-NP-Z2-9]{4,8}$/.test(answer)) throw new Error('Invalid CAPTCHA characters')
  const width = 30 + answer.length * 34, height = 76
  const pixels = Buffer.alloc(width * height * 3)
  for (let i = 0; i < pixels.length; i += 3) pixels.set([20, 24, 33], i)
  const dot = (x, y, color) => {
    x = Math.round(x); y = Math.round(y)
    if (x >= 0 && x < width && y >= 0 && y < height) pixels.set(color, (y * width + x) * 3)
  }
  for (let i = 0; i < 550; i++) dot(crypto.randomInt(width), crypto.randomInt(height), [70, 81, 99])
  for (const [i, char] of [...answer].entries()) {
    const angle = (crypto.randomInt(41) - 20) * Math.PI / 180
    const c = Math.cos(angle), s = Math.sin(angle), cy = 36 + crypto.randomInt(11) - 5
    for (let y = 0; y < 42; y++) for (let x = 0; x < 25; x++) {
      if (!(FONT[char][Math.floor(y / 6)] & (1 << (4 - Math.floor(x / 5))))) continue
      dot(28 + i * 34 + (x - 12) * c - (y - 21) * s, cy + (x - 12) * s + (y - 21) * c, [185, 203, 226])
    }
  }
  for (let i = 0; i < 3; i++) {
    const offset = crypto.randomInt(height), phase = crypto.randomInt(30)
    for (let x = 0; x < width; x++) dot(x, offset + Math.sin((x + phase) / 20) * 9, [102, 117, 138])
  }
  const rows = Buffer.alloc(height * (width * 3 + 1))
  for (let y = 0; y < height; y++) pixels.copy(rows, y * (width * 3 + 1) + 1, y * width * 3, (y + 1) * width * 3)
  const header = Buffer.alloc(13)
  header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', zlib.deflateSync(rows)), chunk('IEND', Buffer.alloc(0))])
}

module.exports = { png }
