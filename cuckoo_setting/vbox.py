from pyvirtualdisplay import Display
import subprocess as sp

disp = Display().start()

sp.call(["virtualbox"])
