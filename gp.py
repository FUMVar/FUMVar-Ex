import perturbation as p
import analysis as anal
import os
import sys
import lief
import time
import ssdeep
import random
import numpy as np
import json

apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)

# pertlist = ['overlay_append', 'upx_pack', 'upx_unpack', 'remove_signature', 'remove_debug', 'break_optional_header_checksum', 'inject_random_codecave', 'section_rename', 'pert_dos_stub', 'pert_bin_name', 'pert_optional_header_dllchlist', 'pert_optional_header_dllch', 'pert_rich_header', 'pert_dos_header', 'section_add', 'section_append']

pertlist = ["overlay_append",'upx_pack', 'upx_unpack',"inject_random_codecave", "section_rename", "pert_dos_stub", "pert_optional_header_dllchlist", "pert_rich_header", "pert_dos_header", "section_add", "section_append", "pert_optional_header", "pert_coff_header", "pert_data_directory","custom_packer"]


one_time = ['upx_unpack','upx_pack','break_optional_header_checksum','remove_signature','remove_debug'] 

def difference(fbytes1, fbytes2):
    hash1 = ssdeep.hash(fbytes1)
    hash2 = ssdeep.hash(fbytes2)
    
    return 100 - ssdeep.compare(hash1, hash2)

class origin:
    def __init__(self,fname,fbytes):
        self.name = fname
        self.fbytes = fbytes
        # self.cuckoosig = anal.get_cuckoo_report(fname)["signatures"]
        self.superset = open("superset/"+anal.search_file_name(fname).replace(".exe",".txt")).read().split("\n")[:-1]
        self.md5 = anal.send_vt_scan(fname,random.choice(apikeylist))
        self.vt_result, self.vt_dlist = anal.vt_analysis_prev(self.md5)
        # self.vt_dlist = [data for data in vt_report["scans"].keys() if vt_report["scans"][data]["detected"] == True]
        # print (self.vt_dlist)
        

class Chromosome:
    def __init__(self, fbytes):
        self.fbytes = fbytes
        self.pert = []
        self.functional = None
        self.vt_result = None
        self.diff = None
        # self.vt_report = None
        self.vt_dlist = None
        self.score = 0
        self.one = []
        self.pert_score = 0
        self.vtscore = 0
        self.prev_pert = []
        self.fname = None
        self.md5 = None

    def perturb(self,chosen_pert,initial=False):
        self.pert = chosen_pert
        for pert in chosen_pert:
            self.fbytes = eval("p."+pert+"(self.fbytes)")


    def past_scoring(self, diff, vt_result, functional):
        self.functional = functional
        self.vt_result = vt_result
        self.diff = diff
        if functional:
            self.score = 50 + diff + (100 - vt_result*100)
            self.vtscore = 50 + diff + (100 - vt_result*100)
            self.pert_score = 0
        else:
            self.score = 0

    def scoring(self):
        if self.functional:
            self.score = 100 + (100 - self.vt_result) + self.diff
        else:
            self.score = 100 - self.vt_result + self.diff

        # print (self.score)
    
    def scoring_without_vt(self,diff,functional):
        self.functional = functional
        self.diff = diff
        if functional:
            # self.score = 50 + diff + (100 - vt_result*100)
            if self.vtscore !=0:
                self.score = self.vtscore = self.vtscore + self.pert_score + diff
            else:
                self.score = 50 + self.pert_score + diff
        else:
            self.score = 0

class GP:
    def __init__(self, fbytes, population, pertnum, output_path, original):
        random.seed(None)
        self.population = []
        self.size = population
        self.pertnum = pertnum
        self.output_path = output_path
        # self.skip = skip
        ### change here ###
        if not os.path.exists(original.name.replace(".exe","_prev0.exe")):
            for i in range(population):
                chosen_pert = random.sample(pertlist,self.pertnum) 
                member = Chromosome(fbytes)
                member.perturb(chosen_pert,initial=True)
                self.population.append(member)
            self.generationnum = 1
        else:
            res = open(original.name.replace("malware","result").replace(".exe",".txt"))
            dres = res.read().split("\n\n")[-3].split("\n")
            # print (dres)
            for i in range(population):
                data = dres[i+1].split(": ")[1].split(", ")
                # print (data)

                fn = original.name.replace(".exe","_prev"+str(i)+".exe")
                fbytes = open(fn,"rb").read()
                member = Chromosome(fbytes)
                member.fname = original.name.replace(".exe","_m"+str(i+1)+".exe")
                with open(member.fname,"wb") as wf:
                    wf.write(fbytes)

                member.md5 = data[0]
                member.vt_result = float(data[1]) # vt_score
                member.functional = bool(data[2]) # functionality
                member.diff = int(data[3]) # difference
                member.pert = eval(",".join(data[4:6]))
                
                # print (member.pert)
                
                if data[6] == "[]":
                    member.prev_pert = []
                    j = 6
                else:
                    for j in range(6,len(data)):
                        if "]]" in data[j]:
                            break
                    member.prev_pert = eval(",".join(data[6:j+1]))

                member.vt_dlist = eval(",".join(data[j+1:]))
                member.scoring()

                self.population.append(member)

            self.generationnum = int(dres[0].split(" ")[0])
        # print (self.generationnum)

    def score(self,original):
        i=1
        chosen_idx = random.randrange(apilen)
        
        # Send the sample to VirusTotal 
        for pop in self.population:
            if pop.vt_result != None:
                i+=1
                continue
            # p.build_lief(pop.fbytes,original.name)
            p.build_lief_name(pop.fbytes,original.name,"m"+str(i))
            pop.fname = original.name.replace(".exe","_m"+str(i)+".exe")
            # print (pop.fname)
            pop.diff = difference(original.fbytes,pop.fbytes)
            pop.md5 = anal.send_vt_scan(pop.fname,apikeylist[(chosen_idx+i)%apilen])
            time.sleep(5)
            i+=1
        
        # Funtionality check
        stime = time.time()
        ck = 0
        for pop in self.population:
            if pop.functional != None:
                continue
            
            for pop2 in self.population:
                if pop2 in self.population:
                    if pop2.fname == pop.fname:
                        continue
                    if pop2.fbytes == pop.fbytes and pop2.functional != None:
                        pop.functional = pop2.functional
                        ck = 1
            if ck == 1:
                ck = 0
                continue

            pop.functional = anal.func_check_superset(original,pop.fname)

            with open(self.output_path.replace(".txt","_suc_rate.txt"),"a") as wf:
                wf.write("prev_perturbation, perturbation, functionality: "+ str(pop.prev_pert)+", "+str(pop.pert)+", "+str(pop.functional)+"\n")
        
        
        ftime = time.time()
        #  VirusTotal result check
        
        if ftime - stime < 70:
            time.sleep(70-(ftime-stime))

        ck = 0
        for pop in self.population:
            if pop.vt_result != None:
                continue

            for pop2 in self.population:
                if pop2 in self.population:
                    if pop2.fname == pop.fname:
                        continue
                    if pop2.fbytes == pop.fbytes and pop2.vt_result != None:
                        pop.vt_result = pop2.vt_result
                        pop.vt_dlist = pop2.vt_dlist
                        ck = 1
            if ck == 1:
                ck = 0
                continue

            if pop.functional:        
                pop.vt_result, pop.vt_dlist = anal.vt_analysis_prev(pop.md5)
            else:
                pop.vt_result, pop.vt_dlist = 1.0, []
            time.sleep(10)
            # pop.vt_dlist = [data for data in vt_report["scans"].keys() if vt_report["scans"][data]["detected"] == True]

            pop.scoring()
        self.population = sorted(self.population, key=lambda pop: pop.score,reverse=True)

    def selection(self, original):
        self.score(original)
        self.population = self.population[:self.size]
        for i in range(self.size):
            with open(original.name.replace(".exe","_prev"+str(i)+".exe"),"wb") as wf:
                wf.write(self.population[i].fbytes)

    def mutate(self,prob):
        populationlist = list(self.population)
        for pop in populationlist[:int(self.size/2)]:#self.population:
            new_pop = Chromosome(bytes(pop.fbytes))
            new_pop.pert_score = pop.pert_score
            new_pop.vtscore = pop.vtscore
            new_pop.prev_pert = list(pop.prev_pert)
            new_pop.prev_pert.append(list(pop.pert))

            nchosen_pert = random.sample(pertlist,self.pertnum)
                
            new_pop.perturb(nchosen_pert)
            self.population.append(new_pop)

        for pop in populationlist[int(self.size/2):]:
            if random.random() < prob:
                new_pop = Chromosome(bytes(pop.fbytes))
                new_pop.pert_score = pop.pert_score
                new_pop.vtscore = pop.vtscore
                new_pop.prev_pert = list(pop.prev_pert)
                new_pop.prev_pert.append(list(pop.pert))

                nchosen_pert = random.sample(pertlist,self.pertnum)

                new_pop.perturb(nchosen_pert)
                self.population.append(new_pop)

    def generation(self,original,gnum):
        self.score(original)
        # self.score_without_vt(original)

        if self.generationnum == 1:
            with open(self.output_path,"a") as wf:
                wf.write("1 generation\n")
            
            func = 0
            for i in range(self.size):
                if self.population[i].functional == False:
                    func+=1

                with open(self.output_path,"a") as wf:
                    # print ("* Member "+ str(i))
                    # print ("Malware Functionality: "+ str(self.population[i].functional))
                    # print ("VirusTotal detection rate: " + str(self.population[i].vt_result))
                    # print ("Applied perturbations: " + str(self.population[i].pert))
                    # print ("Previously applied perturbations: " + str(self.population[i].prev_pert))
                    # print ("")
                    wf.write("MD5, VT, Functinoal, ssdeep difference, perturbation list, previous perturbation list, VT detection list: "+ str(self.population[i].md5)+", "+str(self.population[i].vt_result)+", "+str(self.population[i].functional)+", "+str(self.population[i].diff)+", "+str(self.population[i].pert)+", "+str(self.population[i].prev_pert)+", "+str(self.population[i].vt_dlist)+"\n")
                # print (self.population[i].score, self.population[i].vt_result, self.population[i].functional, self.population[i].diff, self.population[i].pert)
            with open(self.output_path,"a") as wf:
                wf.write("\n")

            if func == self.size:
                # print (self.output_path, "failed")
                return
            
            # print ("") 
        sgnum = int(self.generationnum) 
        for j in range(self.generationnum, gnum+1):
            # print("* "+str(self.generationnum+1)+" generation\n")
            if self.generationnum != sgnum:
                with open(self.output_path,"a") as wf:
                    wf.write(str(self.generationnum+1)+" generation\n")
            # print (self.generationnum, "generation")
            start_time = time.time()
            self.mutate(0.3)
            self.selection(original)
            end_time = time.time() - start_time
            for i in range(self.size):
                with open(self.output_path,"a") as wf:
                    # print ("* Member "+ str(i))
                    # print ("Malware Functionality: "+ str(self.population[i].functional))
                    # print ("VirusTotal detection rate: " + str(self.population[i].vt_result))
                    # print ("Applied perturbations: " + str(self.population[i].pert))
                    # print ("Previously applied perturbations: " + str(self.population[i].prev_pert))
                    # print ("")
                    wf.write("MD5, VT, Functional, ssdeep difference, perturbation list, previous perturbation list, VT detection list: "+str(self.population[i].md5)+", "+str(self.population[i].vt_result)+", "+str(self.population[i].functional)+", "+str(self.population[i].diff)+", "+str(self.population[i].pert)+", "+str(self.population[i].prev_pert)+", "+str(self.population[i].vt_dlist)+"\n")

                # print (self.population[i].score, self.population[i].vt_result, self.population[i].functional,self.population[i].diff, self.population[i].pert)
            with open(self.output_path,"a") as wf:
                wf.write("\n* takes "+str(end_time)+"\n\n")
            # print ("")
            self.generationnum += 1




