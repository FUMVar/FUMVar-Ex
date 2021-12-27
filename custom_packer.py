import os, getopt, sys
from random import randrange

def change(front):
    if front < 10:
        return str(front)
    elif front == 10:
        return 'A'
    elif front == 11:
        return 'B'
    elif front == 12:
        return 'C'
    elif front == 13:
        return 'D'
    elif front == 14:
        return 'E'
    elif front == 15:
        return 'F'

def key_change(key):
    front = key // 16
    back = key % 16
    return change(front) + change(back)

input_file = None
output_file = None
key = randrange(0, 256)
key_str = '0x' + key_change(key)
argv = sys.argv[1:]

try:
    opts, args = getopt.getopt(argv, "hi:o:", ["input=", "output="])
except getopt.GetoptError:
    print("Usage: python packing.py -o filename -i filename")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: python packing.py -o filename -i filename")
        sys.exit()
    elif opt in ("-i", "--input"):
        input_file = arg
    elif opt in ("-o", "--output"):
        output_file = arg

if input_file is None or output_file is None:
    print("Usage: python packing.py -o filename -i filename")
    sys.exit(2)

fp = open(input_file, 'rb')
buf = fp.read()
fp.close()

packed = '{'
result = [0] * len(buf)

for ch in buf:
    key = ch ^ key
    packed += "'\\x" + hex(key)[2:] + "',"
packed = packed[:-1] + '}'
# print(len(buf))
front = ["#include <stdio.h>", \
         "#include <stdlib.h>", \
        "void unpack_data(char* src, int size) {", \
        "int KEY = " + key_str + ";", \
        "int new_key = 0;", \
        "int i;", \
        "for(i=0; i<size; ++i) {", \
        "new_key = src[i];", \
        "src[i] = src[i] ^ KEY;", \
        "KEY = new_key;", \
        "}", \
        "}", \
        "void main(void){", \
        "char src[" + str(len(buf) + 1) + '] = ' + packed + ';', \
        "int size = " + str(len(buf)) + ';', \
        "unpack_data(src, size);", \
        "FILE *fp = fopen(\"test.exe\", \"wb\");", \
        "fwrite(src, size, 1, fp);", \
        "fclose(fp);", \
        "system(\"test.exe\");", \
        "}"]
fp = open('test.c', 'w')
for line in front:
    fp.write(line + '\n')
fp.close()
os.system('i686-w64-mingw32-gcc test.c -o ' + output_file)
