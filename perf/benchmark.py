import subprocess
import sys
import os
import re
import csv
from datetime import datetime

def csvname(file, add=0):
    original_file = file
    if add != 0:
        split = file.split(".")
        file = "".join([split[0],"-",str(add),'.',split[1]])
        #print(file)
    if not os.path.isfile(file):
        return file
    else:
        return csvname(original_file, add=add+1)

directory = './'
directory = 'client/mountdir'

attempts = 1

myrange = list(range(1, 10, 1)) + list(range(10, 100, 10)) + list(range(100, 1001, 100))
myrange = list(range(1, 20, 5)) + list(range(25, 100, 25)) + list(range(100, 1001, 100))
myrange = [16]

dimunit = 'K'

#sysbench parameters
threads = '1'
blocksize = '8K'
rndseq = 'seqrewr' #sequential
rndseq = 'rndrw' #random

heading = ['Dimension (' + dimunit + ')', 'Reads/s', 'Writes/s', 'Fsyncs/s', 'Read (MiB/s)', 'Written (MiB/s)', 'Latency Avg (ms)']
now = datetime.now()

filename = input('Name for benchmark: ')
filename = csvname('benchmark-'+filename+'-'+rndseq+'.csv')

with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(heading)

for dimnum in myrange:
    i=0
    while i<attempts:
        dim = str(dimnum)+dimunit
        print("Testing "+dim+" file attempt #"+str(i+1)+"...")
        result = {}

        # preparing file
        subprocess.run(['sysbench', 'fileio', '--threads='+threads, '--file-total-size=' +
                        dim, '--file-test-mode='+rndseq, '--file-num=1','--file-block-size='+blocksize, 'prepare'], cwd = directory, stdout=subprocess.PIPE)

        # benchmark
        if rndseq == 'seqrewr': #nel caso sequenziale devo combinare manualmente read and write
            output_r = subprocess.run(['sysbench', 'fileio', '--threads='+threads, '--file-total-size=' +
                                 dim, '--file-test-mode=seqrd', '--file-num=1','--file-block-size='+blocksize, 'run'], cwd = directory, stdout=subprocess.PIPE)
            output_w = subprocess.run(['sysbench', 'fileio', '--threads='+threads, '--file-total-size=' +
                                 dim, '--file-test-mode=seqwr', '--file-num=1','--file-block-size='+blocksize, 'run'], cwd = directory, stdout=subprocess.PIPE)
            #print(output_w)
            
            # decoding and parsing stdout
            for row in output_r.stdout.decode('utf-8').splitlines():
                if ': ' in row:
                    key, value = row.split(': ')
                    if float(re.sub('\D', '', value.strip())) != 0 :
                        result[key.strip()] = value.strip()

            #in questo modo vengono sovrascritti tutti i valori tranne quelli non presenti nella read, ovvero writes, fsyncs, written
            #avg latency si lascia quella in scrittura, sperimentalmente in lettura la latenza è 0
            for row in output_w.stdout.decode('utf-8').splitlines():
                if ': ' in row:
                    key, value = row.split(': ')
                    if float(re.sub('\D', '', value.strip())) != 0 : #controllo che i valori non siano 0 per evitare di sovrascrivere i precedenti
                        result[key.strip()] = value.strip()
                    elif key.strip() == 'avg' : #a volte non si prende avg, mi assicuro che venga scritto
                        result[key.strip()] = value.strip()
            
        else : #nel caso random
            output = subprocess.run(['sysbench', 'fileio', '--threads='+threads, '--file-total-size=' +
                                 dim, '--file-test-mode='+rndseq, '--file-num=1','--file-block-size='+blocksize, 'run'], cwd = directory, stdout=subprocess.PIPE)
            #output = subprocess.check_output("sysbench --threads=16 --test=fileio --file-total-size="+dim+" --file-test-mode=rndrw --file-num=1 run", shell=True)

            #print(output.stdout)
            
            # decoding and parsing stdout
            for row in output.stdout.decode('utf-8').splitlines():
                if ': ' in row:
                    key, value = row.split(': ')
                    result[key.strip()] = value.strip()
                    
        # cleanup
        subprocess.run(['sysbench', 'fileio', 'cleanup'], cwd = directory, stdout=subprocess.PIPE)

        #print(result)
        result = [dimnum, result['reads/s'], result['writes/s'], result['fsyncs/s'],
                  result['read, MiB/s'], result['written, MiB/s'], result['avg']]
        #results.append(result)

        with open(filename, "a", newline="") as f:
            writer = csv.writer(f)
            #writer.writerows(heading)
            writer.writerow(result)
    
        i += 1


"""with open(csvname('benchmark-'+filename+'-'+rndseq+'.csv'), "w", newline="") as f:
    writer = csv.writer(f)
    #writer.writerows(heading)
    writer.writerows(results)
    
print('CSV file written succesfully')
#print(results)"""
