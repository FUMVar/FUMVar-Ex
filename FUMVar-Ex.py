import sys
import os
from argparse import ArgumentParser
import gp

if __name__ == "__main__":
    parser = ArgumentParser()    
    parser.add_argument("-i", type=str, help="Path for binary input", dest="input_path", required=True)
    parser.add_argument("-o", type=str, help="Path for result", dest="output_path", required=True)
    parser.add_argument("-p", type=int, help="Number of population (default=4)", dest="population")
    parser.add_argument("-m", type=int, help="Number of perturbation per generation (default=4)", dest="perturbation")
    parser.add_argument("-g", type=int, help="Number of generation (default=100)", dest="generation")
    parser.add_argument("-s", type=int, help="Number of skip time for VirusTotal scan generation (default=5)", dest="skip")
    
    args = parser.parse_args()
    population = 4
    perturbation = 4
    generation = 100
    skip = 5
    input_path = args.input_path
    output_path = args.output_path

    if args.population:
        population = args.population
    if args.perturbation:
        perturbation = args.perturbation
    if args.generation:
        generation = args.generation
    if args.skip:
        skip = args.skip
    
    print ("* Scanning original malware sample")
    fbytes = open(input_path,"rb").read()
    original = gp.origin(input_path,fbytes)

    if not os.path.exists(os.path.exists(original.name.replace(".exe","_prev0.exe"))):
        with open(output_path,"a") as wf:
            wf.write("original file: "+input_path+"\nVT result: "+str(original.vt_result)+"\nVT detection list:"+str(original.vt_dlist)+"\n\n")
    print ("\nOriginal file: "+ input_path)
    # print ("Supser set: ", original.superset)
    print ("VirusTotal detection rate: "+ str(original.vt_result))
    print ("") 
     
    print ("* Starting GP malware generation\n")
    # print ("* 1 generation\n")
    g = gp.GP(fbytes,population,perturbation,output_path,original)
    # exit(0)
    g.generation(original,generation)
    

