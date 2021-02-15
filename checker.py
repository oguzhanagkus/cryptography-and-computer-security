import os, sys, getopt
from aes import *

class DocumentChecker:
  """
  Create hash of a file and add it to end of the file.
  It means it is signed with a key.
  Sender sign the file, reviever check the file if someone change it.
  """
  _seperator = "~"
  _init_vector = 16 * "0".encode()
  _append_size = 16 + 2

  def __init__(self, file_name, key):
    """
    Initialize with given file name and key.
    Check if given file exists.
    """
    try:
      self._file_name = file_name
      self._encryptor = AES(key.encode())
      self._document = open(self._file_name, "rb+")
    except Exception as error:
      print(error)
      sys.exit(1)

  def __del__(self):
    """
    Destructor for closing the file.
    """
    try:
      self._document.close()
    except:
      pass

  def is_signed(self):
    """
    Check if a hash is added to file.
    """
    file_size = os.stat(self._file_name).st_size
    self._document.seek(file_size - self._append_size)
    last = self._document.read()
    self._document.seek(0)

    if not (chr(last[0]) == self._seperator and chr(last[-1]) == self._seperator):
      return False
    else:
      return True

  def add_sign(self):
    """
    Create a hash usign cipher block chaining mode of AES encryption. Last 16-byte is the hash of file.
    If file is already signed, it removes previous sign and create new one.
    """
    if self.is_signed():
       self.remove_sign()
    
    data = self._document.read()
    encrypted = self._encryptor.encrypt_cbc(data, self._init_vector)
    hash_value = encrypted[-16:]
    self._document.write(self._seperator.encode() + hash_value + self._seperator.encode())
    print("The document is signed!")

  def remove_sign(self):
    """
    Remove hash from the file if it exist.
    """
    if self.is_signed():
      file_size = os.stat(self._file_name).st_size
      self._document.truncate(file_size - self._append_size)
      print("Sign removed from the document!")
    else:
      print("The document is not signed!")

  def check(self):
    """
    If file is signed, it checks current hash and added hash are matched.
    """
    if self.is_signed():
      data = self._document.read()
      hash_value = data[-self._append_size+1:-1]
      data =  data[:-self._append_size]

      encrypted = self._encryptor.encrypt_cbc(data, self._init_vector)
      current_hash_value = encrypted[-16:]

      if current_hash_value != hash_value:
        print("Hash values did not matched!")
      else:
        print("Hash values matched!")
    else:
      print("The document is not signed!")

##################################################

def usage():
  """
  Show usage of the tool.
  """
  print("This program runs with command line arguments.\n"
        "Available parameters:\n"
        "\t-h --help : help\n"
        "\t-f        : file name or path\n"
        "\t-k        : key file\n"
        "\t-o        : operaion\n"
        "\n"
        "There are 3 operations available:\n"
        "\t'1' --> add_sign() : adds hash to end of file\n"
        "\t'2' --> check() : checks if added hash and current hash are matched\n"
        "\t'3' --> remove_sign() : remove hash from end of file which has added with operion 1\n"
        "\n"
        "Example command: $python3 checker.py -f message.pdf -k key_file.txt -o 1")

def main():
  """
  Main function. Parse command line arguments and interpret them.
  """
  file_name = None
  key = None
  operation = None

  try:
    if len(sys.argv) == 1:
      raise Exception("No arguement passed!")
    opts, args = getopt.getopt(sys.argv[1:], "f:k:o:h", ["help"])
  except Exception as error:
    print(error)
    sys.exit(1)

  for opt, arg in opts:
    if opt in ("-h", "--help"):
      usage()
      sys.exit()
    elif opt == "-f":
      file_name = arg
    elif opt == "-k":
      try:
        with open(arg) as key_file:
          key = key_file.read()
      except Exception as error:
        print(error)
        sys.exit()
    elif opt == "-o":
      operation = arg
    else:
      print("Invalid argument passed.")
      sys.exit(1)
  
  if file_name == None or key == None or operation == None:
    print("Missing argument/s!")
    usage()
    sys.exit(1)

  checker = DocumentChecker(file_name, key)

  if operation == "1":
    checker.add_sign()
  elif operation == "2":
    checker.check()
  elif operation == "3":
    checker.remove_sign()
  else:
    print("Invalid operation.")
    sys.exit(1)

##################################################

if __name__ == "__main__":
  main()