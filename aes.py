import sys

s_box = (
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inverse_s_box = (
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

r_con = (
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
  0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
  0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
  0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def bytes_to_matrix(byte_array):
  """
  Converts 16-byte array to 4x4 matrix.
  """
  matrix = []
  for i in range(0, len(byte_array), 4):
    matrix.append(list(byte_array[i:i+4]))
  return matrix

def matrix_to_bytes(matrix):
  """
  Converts 4x4 matrix to 16-byte array.
  """
  result = []
  for row in matrix:
    for item in row:
      result.append(item)
  return bytes(result)

def xor_bytes(x, y):
  """
  Performs XOR operation between x and y, returns result.
  """
  result = []
  for i, j in zip(x, y):
    result.append(i^j)
  return bytes(result)

def split_blocks(text, block_size=16):
  """
  Split a text into equal sized blocks.
  """
  blocks = []
  for i in range(0, len(text), block_size):
    blocks.append(text[i:i+block_size])
  return blocks

##################################################

class AES:
  """
  Represents Advanced Encryption Standard (AES), supports 128-bit, 192-bit, and 256-bit keys.
  """
  _rounds_by_key_size = {16:10, 24:12, 32:14}

  def __init__(self, key):
    """
    Initializes with given key.
    Generates round keys.
    """
    self._key_size = len(key)
    if self._key_size in self._rounds_by_key_size:
      self._key = key
      self._rounds = self._rounds_by_key_size[self._key_size]
      self._round_keys = self._generate_round_keys(key)
    else:
      print("Invalid key length!")
      sys.exit(1)

  ##################################################

  def _add_round_key(self, block, key):
    """
    Performs XOR between round key and block.
    """
    for i in range(4):
      for j in range(4):
        block[i][j] ^= key[i][j]

  def _sub_bytes(self, block):
    """
    Each byte is replaced with another according to s_box.
    """
    for i in range(4):
      for j in range(4):
        block[i][j] = s_box[block[i][j]]

  def _inv_sub_bytes(self, block):
    """
    Each replaced byte is replaced with another according to inverse_s_box. 
    """
    for i in range(4):
      for j in range(4):
        block[i][j] = inverse_s_box[block[i][j]]
  
  def _shift_rows(self, block):
    """
    The last three rows are shifted vertically to left.
    """
    block[0][1], block[1][1], block[2][1], block[3][1] = block[1][1], block[2][1], block[3][1], block[0][1]
    block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
    block[0][3], block[1][3], block[2][3], block[3][3] = block[3][3], block[0][3], block[1][3], block[2][3]

  def _inv_shift_rows(self, block):
    """
    The last three rows are shifted vertically to right.
    """
    block[0][1], block[1][1], block[2][1], block[3][1] = block[3][1], block[0][1], block[1][1], block[2][1]
    block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
    block[0][3], block[1][3], block[2][3], block[3][3] = block[1][3], block[2][3], block[3][3], block[0][3]

  def _mix_single_column(self, column):
    """
    Combine four bytes of a column.
    """
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    u = column[0]
    column[0] ^= t ^ xtime(column[0] ^ column[1])
    column[1] ^= t ^ xtime(column[1] ^ column[2])
    column[2] ^= t ^ xtime(column[2] ^ column[3])
    column[3] ^= t ^ xtime(column[3] ^ u)

  def _mix_columns(self, block):
    """
    Linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
    """
    for i in range(4):
      self._mix_single_column(block[i])

  def _inv_mix_columns(self, block):
    """
    Inverse mixing operation.
    """
    for i in range(4):
      u = xtime(xtime(block[i][0] ^ block[i][2]))
      v = xtime(xtime(block[i][1] ^ block[i][3]))
      block[i][0] ^= u
      block[i][1] ^= v
      block[i][2] ^= u
      block[i][3] ^= v

    self._mix_columns(block)

  ##################################################

  def _add_padding(self, plain_text):
    """
    Add padding to given plain text with PKCS7 padding to make its size multiple of 16 bytes.
    If the plain text's size is multiple of 16, a block with size 16 will added.
    """
    padding_size = 16 - (len(plain_text) % 16)
    padding = bytes(padding_size * [padding_size])
    return plain_text + padding

  def _remove_padding(self, plain_text):
    """
    Remove padding which is added with _add_padding() method.
    Also it checks the padding is correct.
    """
    padding_size = plain_text[-1]
    text = plain_text[:-padding_size]
    padding = plain_text[-padding_size:]

    for byte in padding:
      if byte != padding_size:
        print("Unrecognized padding!")
        sys.exit(1)

    return text

  ##################################################

  def _generate_round_keys(self, key):
    """
    Generate round keys according to master key.
    It produces
      10+1 round key for 128-bit key,
      12+1 round key for 192-bit key,
      14+1 round key for 256-bit key.
    """
    key_columns = bytes_to_matrix(key)
    iteration_size = self._key_size // 4

    i = 1
    while len(key_columns) < 4 * (self._rounds + 1):
      word = list(key_columns[-1])

      if len(key_columns) % iteration_size == 0:
        word.append(word.pop(0))
        
        for b in range(len(word)):
          word[b] = s_box[word[b]]

        word[0] ^= r_con[i]
        i+=1
      elif self._key_size == 32 and len(key_columns) % iteration_size == 4:
        for b in range(len(word)):
          word[b] = s_box[word[b]]

      word = xor_bytes(word, key_columns[-iteration_size])
      key_columns.append(word)

    result = []
    for i in range(len(key_columns) // 4):
      result.append(list(key_columns[i*4 : (i+1)*4]))

    return result

  ##################################################

  def encrypt_block(self, plain_text):
    """
    Encrypt single block.

    - AddRoundKey (Initial)
    - 9, 11, or 13 rounds:
      - SubBytes
      - ShiftRows
      - MixColums
      - AddRoundKey
    - Final round
      - SubBytes
      - ShiftRows
      - AddRoundKey
    """
    plain_state = bytes_to_matrix(plain_text)
    self._add_round_key(plain_state, self._round_keys[0])

    for i in range(1, self._rounds):
      self._sub_bytes(plain_state)
      self._shift_rows(plain_state)
      self._mix_columns(plain_state)
      self._add_round_key(plain_state, self._round_keys[i])
    
    self._sub_bytes(plain_state)
    self._shift_rows(plain_state)
    self._add_round_key(plain_state, self._round_keys[-1])

    return matrix_to_bytes(plain_state)

  def decrypt_block(self, cipher_text):
    """
    Decrypt single block by applying encrypt operations in reverse order. 
    """
    cipher_state = bytes_to_matrix(cipher_text)

    self._add_round_key(cipher_state, self._round_keys[-1])
    self._inv_shift_rows(cipher_state)
    self._inv_sub_bytes(cipher_state)

    for i in range(self._rounds - 1, 0, -1):
      self._add_round_key(cipher_state, self._round_keys[i])
      self._inv_mix_columns(cipher_state)
      self._inv_shift_rows(cipher_state)
      self._inv_sub_bytes(cipher_state)
    
    self._add_round_key(cipher_state, self._round_keys[0])
    
    return matrix_to_bytes(cipher_state)

  ##################################################

  def encrypt_ecb(self, plain_text):
    """
    Encrypt in electronic codebook mode. Using PKCS7 padding.
    """
    plain_text = self._add_padding(plain_text)

    blocks = []
    for plain_text_block in split_blocks(plain_text):
      block = self.encrypt_block(plain_text_block)
      blocks.append(block)
    
    return b''.join(blocks)

  def decrypt_ecb(self, cipher_text):
    """
    Decrypt in electronic codebook mode. Using PKCS7 padding.
    """
    blocks = []
    for cipher_text_block in split_blocks(cipher_text):
      block = self.decrypt_block(cipher_text_block)
      blocks.append(block)

    plain_text = b''.join(blocks)
    plain_text = self._remove_padding(plain_text)

    return plain_text

  ##################################################

  def encrypt_cbc(self, plain_text, iv):
    """
    Encrypt in cipher block chaining mode. Using PKCS7 padding.
    """
    plain_text = self._add_padding(plain_text)

    blocks = []
    previous = iv
    for plain_text_block in split_blocks(plain_text):
      block = self.encrypt_block(xor_bytes(plain_text_block, previous))
      blocks.append(block)
      previous = block

    return b''.join(blocks)

  def decrypt_cbc(self, cipher_text, iv):
    """
    Decrypt in cipher block chaining mode. Using PKCS7 padding.
    """
    blocks = []
    previous = iv
    for cipher_text_block in split_blocks(cipher_text):
      blocks.append(xor_bytes(previous, self.decrypt_block(cipher_text_block)))
      previous = cipher_text_block

    plain_text = b''.join(blocks)
    return self._remove_padding(plain_text)

  ##################################################

  def encrypt_ofb(self, plain_text, iv):
    """
    Encrypt in output feedback mode. Using PKCS7 padding.
    """
    blocks = []
    previous = iv
    for plain_text_block in split_blocks(plain_text):
      block = self.encrypt_block(previous)
      cipher_text_block = xor_bytes(plain_text_block, block)
      blocks.append(cipher_text_block)
      previous = block

    return b''.join(blocks)

  def decrypt_ofb(self, cipher_text, iv):
    """
    Decrypt in output feedback mode. Using PKCS7 padding.
    """
    blocks = []
    previous = iv
    for cipher_text_block in split_blocks(cipher_text):
      block = self.encrypt_block(previous)
      plain_text_block = xor_bytes(cipher_text_block, block)
      blocks.append(plain_text_block)
      previous = block

    return b''.join(blocks)

##################################################

if __name__ == "__main__":
  pass