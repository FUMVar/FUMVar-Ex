import os
from pyvirtualdisplay import Display
from multiprocessing import Pool, Process
import subprocess as sp

def create_hostonly_net():
    os.system("VBoxManage hostonlyif create")
    os.system("VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1")
    os.system("sudo iptables -t nat -A POSTROUTING -o ens4 -s 192.168.56.0/24 -j MASQUERADE")
    os.system("sudo iptables -A FORWARD -o ens4 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT")
    os.system("sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    os.system("sudo iptables -A POSTROUTING -t nat -j MASQUERADE")
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

def virtualbox():
    disp = Display().start()
    os.system("sudo virtualbox")

def cuckoo_debug():
    os.system("sudo cuckoo --cwd /home/.cuckoo")

def cuckoo_api():
    os.system("sudo cuckoo --cwd /home/.cuckoo api")

def cuckoo_web():
    os.system("sudo cuckoo --cwd /home/.cuckoo web")


if __name__ == "__main__":
    network_list = sp.check_output(["ifconfig"])
    if "vboxnet0" not in network_list.decode("ascii"):
        create_hostonly_net()

    p1 = Process(target=virtualbox, args=())
    p2 = Process(target=cuckoo_debug, args=())
    p3 = Process(target=cuckoo_api, args=())
    p4 = Process(target=cuckoo_web, args=())
    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p1.join()
    p2.join()
    p3.join()
    p4.join()
