# FUMVar-Ex
This a extended framework from FUMVar (https://github.com/FUMVar/FUMVar).

## Installation
```
$ git clone https://github.com/FUMVar/FUMVar-Ex.git
```

## Requirements
* python 3.6 version
* ssdeep
* lief
* numpy
* requests
* pandas
* pefile
* pyvirtualdisplay

## Virtual environment setting
```
$ virtualenv -p python3 venv
$ . ./venv/bin/activate
(venv) $ pip install -r requirements.txt
```

## Cuckoo sandbox execution
You need to set 5 virtual machines for Cuckoo sandbox anaylsis. And run each code in cuckoo_setting for with different command window.
```
(venv) $ cd cuckoo_setting
(venv) $ python vbox.py
```
```
(venv) $ python cuckoo_api.py
```
```
(venv) $ python cuckoo_debug.py
```

## How to run
Before you run the code you have to insert the VirusTotal api key to the `vt_api_key` file. You can add multiple VirusTotal api key in vt_api_key.
```
$ vim vt_api_key

#### insert your api key ####
```
After insert VirusTotal api key. This is an example, these keys are not valid.
```
$ vim vt_api_key

sdfsafasdfhghjkhsadfghsajdfgjhasghjfdgasjhfghasjdgfjhasgfhjasgfj
dfajshfkjsahfhjk1h32kj389yf8as9h12389dghfsa8fyh91huhfjksadhfjkhs
...
```

Also, you have to add list of superset of each malware sample. A superset consists of field-value from Cuckoo sandbox report as you can see in the `superset/sample.txt`.
```
$ vim superset/sample.txt

name-antisandbox_idletime
name-raises_exception
name-injection_ntsetcontextthread
name-removes_zoneid_ads
api-GlobalMemoryStatusEx
...
```

You can see the information by running FUMVar with --help option.
```
(venv) $ python FUMVar-Ex.py --help

usage: FUMVar-Ex.py [-h] -i INPUT_PATH -o OUTPUT_PATH [-p POPULATION]
                 [-m PERTURBATION] [-g GENERATION] [-s SKIP]

optional arguments:
  -h, --help       show this help message and exit
  -i INPUT_PATH    Path for binary input
  -o OUTPUT_PATH   Path for result
  -p POPULATION    Number of population (default=4)
  -m PERTURBATION  Number of perturbation per generation (default=4)
  -g GENERATION    Number of generation (default=100)
  -s SKIP          Number of skip time for VirusTotal scan generation
                   (default=5)

```

### Sample code for running and result
```
(venv) $ python FUMVar-Ex.py -i sample/sample.exe -o result/result.txt -p 2 -g 200 -m 1 -s 1
* Scanning original malware sample

Original file: sample/sample.exe
VirusTotal detection rate: 0.8235294117647058

* Starting GP malware generation

* 1 generation

* Member 0
Malware Functionality: True
VirusTotal detection rate: 0.7222222222222222
Applied perturbations: ['upx_pack']
Previously applied perturbations: []

* Member 1
Malware Functionality: True
VirusTotal detection rate: 0.7746478873239436
Applied perturbations: ['pert_dos_stub']
Previously applied perturbations: []

* 2 generation

* Member 0
Malware Functionality: True
VirusTotal detection rate: 0.7222222222222222
Applied perturbations: ['upx_pack']
Previously applied perturbations: []

* Member 1
Malware Functionality: True
VirusTotal detection rate: 0.7323943661971831
Applied perturbations: ['section_add']
Previously applied perturbations: [['upx_pack']]
```
