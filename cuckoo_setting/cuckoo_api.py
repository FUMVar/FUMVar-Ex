import os
# from pyvirtualdisplay import Display
from multiprocessing import Pool, Process
import subprocess as sp

# port range (8090~8094)
num =5 
def cuckoo_api(n):
    os.system("cuckoo --cwd path/cuckoo_conf"+str(n)+" api"+" -p "+str(8089+n))

if __name__ == "__main__":
    with Pool(num) as p:
        p.map(cuckoo_api, [i for i in range(1,num+1)])

