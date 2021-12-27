import os
# from pyvirtualdisplay import Display
from multiprocessing import Pool, Process
import subprocess as sp

num=5

def cuckoo_debug(n):
    os.system("/data/beomjin/cuckoo/cuckoovenv/bin/cuckoo --cwd /data/beomjin/cuckoo/conf_path/cuckoo"+str(n))

if __name__ == "__main__":
    with Pool(num) as p:
        p.map(cuckoo_debug, [i for i in range(2,num+2)])

