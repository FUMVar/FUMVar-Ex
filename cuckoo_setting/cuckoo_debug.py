import os
# from pyvirtualdisplay import Display
from multiprocessing import Pool, Process
import subprocess as sp

num=5

def cuckoo_debug(n):
    os.system("cuckoo --cwd path/cuckoo_conf"+str(n))

if __name__ == "__main__":
    with Pool(num) as p:
        p.map(cuckoo_debug, [i for i in range(1,num+1)])

