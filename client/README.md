# ABEBox Client
The ABEBox Client is the component that needs to be installed on user devices. It takes care of all the operations 
related to the protection of data contents. It uses the *FUSE* library by making transparent to the user all the 
underling processes and leaving him/her only the operations related to the access policies to apply to data that needs 
to be protected.
Policies are the same ones defined in ABE, so they are monotonic boolean expressions consisting of *AND*, *OR* and 
*K-out-of-N* (threshold) operands. An example of a valid policy is the following:
> ( IT-Department OR ProjectTeam ) AND ProjectManager
>
ABEBox Client allows user to work on data in a clear form but saving his/her activities on protected files.

## Installation

### Python
In order to run ABEBox Client, first you have to install *python3* on your Linux distribution. 

### Charm library
Next, you have to install Charm library, used for CP-ABE operations. You can download the github repository [here]
[charm] and, from a shell inside the downloaded folder, you can install it by executing the following commands
> sudo apt update && apt install --yes build-essential flex bison wget subversion m4 python3 python3-dev 
> python3-setuptools libgmp-dev libssl-dev
>
> sudo wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd /pbc-0.5.14 && 
> ./configure LDFLAGS="-lgmp" && make && make install && ldconfig
> 
> cp . charm/
> 
> cd charm && ./configure.sh && make && make install && ldconfig
>

### FUSE library
To install FUSE library, you have to execute the following command
> sudo apt install libfuse-dev
> 

### ABEBox Client
Next, if you already have not done it, download the ABEBox Client and open a shell inside its folder. Now you have to 
run the following command to install all the required Python dependencies
> pip3 install -r requirements.txt
>

## Run
Before running ABEBox Client, you should create a local directory where the Client will temporary store data in clear 
form, before protect and save it inside the destination directory.

You can now start the ABEBox Client by simply running the following command
> python3 abebox.py basedir mountdir
> 
where *basedir* is the destination folder where protected data is stored and *mountdir* is the previously created folder
with temporary data in clear form. 

## Issues
To stop ABEBox Client, you just need to press *Ctrl+C*. If any error occurs, you may have to delete *mountdir* folder. 
If this operation is not possible, try to execute
> fusermount -u mountdir
>


[charm]: https://github.com/JHUISI/charm