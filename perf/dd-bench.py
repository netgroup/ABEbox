import subprocess
import os
import sys
import csv
import time

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


def write_test(file_size, random, bs, directory) :
    # rimuovo il file di test
    if os.path.isfile(directory + 'test') :
        os.remove(directory + 'test')

    #print('dd if="/dev/zero" of="./test" bs=' + str(bs) + ' count=' + str(int(file_size/bs)))
    proc = subprocess.run('dd if="/dev/zero" of="./test" bs=' + str(bs) + ' count=' + str(int(file_size/bs)), shell=True, cwd = directory, capture_output=True)
    #(out, err) = proc.communicate()
    #res_output = out.split('\n')[2].split()
    res_output = proc.stderr.decode('utf-8').splitlines()[2].split()
    #print(res_output)
    written_bytes, time_sec = res_output[0] , res_output[7]
    return float(written_bytes.replace(',','.')) / float(time_sec.replace(',','.')) / pow(10, 6)


def read_test(file_size, random, bs, directory) :
    # rimuovo il file di test
    if os.path.isfile(directory + 'test') :
        os.remove(directory + 'test')

    # creo il file
    subprocess.run('dd if="/dev/zero" of="./test" bs=' + str(bs) + ' count=' + str(int(file_size/bs)), shell=True, cwd = directory, capture_output=True)
    proc = subprocess.run('dd if="./test" of="/dev/null" bs=' + str(bs) + ' count=' + str(int(file_size/bs)), shell=True, cwd = directory, capture_output=True)
    #(out, err) = proc.communicate()
    #res_output = out.split('\n')[2].split()
    res_output = proc.stderr.decode('utf-8').splitlines()[2].split()
    #print(res_output)
    read_bytes, time_sec = res_output[0] , res_output[7]
    return float(read_bytes.replace(',','.')) / float(time_sec.replace(',','.')) / pow(10, 6)


def x_filesize(myrange, stat_attempts, block_size, directory, random_op) :
    # Apro CSV
    heading = ['File size (KB)', 'Reads/s', 'Writes/s', 0, 'Read Throughput (MB/s)', 'Write Throughput (MB/s)', 0]
    filename = input('Name for benchmark: ')

    if random_op:
        rndseq = "random"
    else :
        rndseq = "sequential"
    filename = csvname('benchmark-'+filename+'-'+rndseq+'.csv')

    with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(heading)
    
    thr_w = 0
    thr_r = 0

    for dimnum in myrange:
        for s in range(stat_attempts):
            print("Testing file", dimnum/1024, "KB")

            #Scrivo
            thr_w = (write_test(dimnum, random_op, block_size, directory))

            #Leggo
            thr_r = (read_test(dimnum, random_op, block_size, directory))

            # Appendo su CSV
            with open(filename, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([dimnum/1024, 0, 0, 0, thr_r, thr_w, 0])


def x_chunksize(version, myrange, stat_attempts, file_dim, block_size, directory, random_op) :
    # Apro CSV
    heading = ['Chunk size (KB)', 'Reads/s', 'Writes/s', 0, 'Read Throughput (MB/s)', 'Write Throughput (MB/s)', 0]
    filename = input('Name for benchmark: ')

    if random_op:
        rndseq = "random"
    else :
        rndseq = "sequential"
    filename = csvname('benchmark-'+filename+'-'+rndseq+'.csv')

    with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(heading)
    
    thr_w = 0
    thr_r = 0

    for dimnum in myrange:
        for s in range(stat_attempts):
            cs = dimnum + 32
            print("Testing chunk size", cs/1024, "KB")

            # Run Abebox
            abe = subprocess.Popen('python3.6 ' + version + ' basedir/ mountdir/ -chunk_size ' + str(cs), shell=True, cwd = directory + '../', stdout=subprocess.PIPE)
            time.sleep(2)

            #Scrivo
            thr_w = (write_test(file_dim, random_op, block_size, directory))

            #Leggo
            thr_r = (read_test(file_dim, random_op, block_size, directory))

            #Kill ABE
            subprocess.run('fusermount -uz mountdir', shell=True, cwd = directory + '../', stdout=subprocess.PIPE)

            # Appendo su CSV
            with open(filename, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([dimnum/1024, 0, 0, 0, thr_r, thr_w, 0])


def x_reenc(version, myrange, stat_attempts, file_dim, block_size, chunk_size, directory, random_op) :
    # Apro CSV
    heading = ['Re-encryption operations', 'Reads/s', 'Writes/s', 0, 'Read Throughput (MB/s)', 'Write Throughput (MB/s)', 0]
    filename = input('Name for benchmark: ')

    if random_op:
        rndseq = "random"
    else :
        rndseq = "sequential"
    filename = csvname('benchmark-'+filename+'-'+rndseq+'.csv')

    with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(heading)
    
    thr_w = 0
    thr_r = 0

    for dimnum in myrange:
        for s in range(stat_attempts):
            print("Testing with n.", dimnum, "re-encryptions")

            # Run Abebox
            abe = subprocess.Popen('python3.6 ' + version + ' basedir/ mountdir/ -chunk_size ' + str(chunk_size) + ' -init_re_encs_num ' + str(dimnum), shell=True, cwd = directory + '../', stdout=subprocess.PIPE)
            time.sleep(2)

            #Scrivo
            thr_w = (write_test(file_dim, random_op, block_size, directory))
            #print("thrW", thr_w)

            #Leggo
            thr_r = (read_test(file_dim, random_op, block_size, directory))
            #print("thrR", thr_r)

            #Kill ABE
            subprocess.run('fusermount -uz mountdir', shell=True, cwd = directory + '../', stdout=subprocess.PIPE)

            # Appendo su CSV
            with open(filename, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([dimnum, 0, 0, 0, thr_r, thr_w, 0])


# PARAMETERS
directory = sys.argv[1] if len(sys.argv) >= 2 else './' # default current directory
random_op = bool(int(sys.argv[2])) if len(sys.argv) >= 3 and int(sys.argv[2]) != 0 else bool(0) # default sequenziale
stat_attempts = int(sys.argv[3]) if len(sys.argv) >= 4 and int(sys.argv[3]) != 0 else 1

version = 'abebox.py'
version = 'abebox_hash_chain.py'
block_size = 4*1024 # in bytes
print("Directory: ", directory)
print("Block size: ", block_size/1024, "KB")

# VARIO IL FILESIZE E LE METTO SULLE X
dim_range = list(range(512*1024, 3*1024*1024+1, 512*1024)) # chunksize in bytes
dim_range = [4*1024, 256*1024, 1024*1024, 3*1024*1024]
x_filesize(dim_range, stat_attempts, block_size, directory, random_op)

# VARIO I CHUNKSIZE E LI METTO SULLE X, FISSATA LA DIMENSIONE DEL FILE
file_dim = 3*1024*1024
cs_range = list(range(512*1024, 3*1024*1024+1, 512*1024)) # chunksize in bytes
#cs_range = [4*1024, 256*1024, 1024*1024, 3*1024*1024]
#x_chunksize(version, cs_range, stat_attempts, file_dim, block_size, directory, random_op)

# VARIO INIT RE-ENCRYPTIONS
file_dim = 3*1024*1024
reenc_range = list(range(0, 11, 1)) # re-encryption numbers
#reenc_range = [0, 1, 2]
chunk_size = block_size + 32
#x_reenc(version, reenc_range, stat_attempts, file_dim, block_size, chunk_size, directory, random_op)

"""t = write_test(3145728, random_op)
print(t)
t = read_test(3145728, random_op)
print(t)"""

#read dd if="/tmp/test" of="/dev/null" bs=1024 count=1024