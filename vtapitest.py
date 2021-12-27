import analysis as a
import time

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)

hashvalue = "00372c59a05ba9cce6ab5a40b28e8bd7db5a284e019dbaaaccf30408ec14f26f"

for api in apikeylist:
    print (api)
    try:
        a.get_vt_report(hashvalue,api)
        print ("success")
    except:
        print ("failed")
    
    time.sleep(3)
