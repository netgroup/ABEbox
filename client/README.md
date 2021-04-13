# ABEBox Client
The ABEBox Client is the component that needs to be installed on user devices. It takes care of all the operations 
related to the protection of data contents. It uses the *FUSE* library by making transparent to the user all the 
underling processes and leaving him/her only the operations related to the access policies to apply to data that needs 
to be protected.
Policies are the same ones defined in ABE, so they are monotonic boolean expressions consisting of *AND*, *OR* and 
*K-out-of-N* (threshold) operands. An example of a valid policy is the following:
> ( IT-Department OR ProjectTeam ) AND ProjectManager

ABEBox Client allows user to work on data in a clear form but saving his/her activities on protected files.

## Installation 
We provide two different procedures to install the ABEBox Client. The former is for an installation on the native OS, 
while the latter will create a ready-to-use Docker container. 

### Native installation

#### Required libraries
Before you install the ABEBox Client, you have to install Python3, FUSE, Charm and other libraries, used for its correct 
execution. You can download Charm from the github repository [here][charm] or by using the following command
> git clone https://github.com/JHUISI/charm

From a shell inside the downloaded folder, you can install Charm and all the required libraries by executing the 
following commands
> sudo apt update && apt install --yes build-essential flex bison wget subversion m4 python3.8 python3-dev 
> python3-setuptools python3-pip libgmp-dev libssl-dev libfuse-dev git libsasl2-dev libldap2-dev
>
> sudo wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && tar xvf pbc-0.5.14.tar.gz && cd pbc-0.5.14 && 
> ./configure LDFLAGS="-lgmp" && make && make install && ldconfig
> 
> cp -r ../../charm /charm
> 
> cd /charm && ./configure.sh && make && make install && ldconfig

#### ABEBox Client
Next, if you already have not done it, download the ABEBox Client and open a shell inside its folder. Now you have to 
run the following command to install all the required Python dependencies
> pip3 install --upgrade pip && pip3 install -r requirements

### Docker installation
If you want to run the ABEBox Client on an indipendent Docker container, you need the build the Dockerfile that you can 
find inside this folder by executing the following command (don't forget the dot at the end!)
> docker build -f ABEBoxClient_Dockerfile -t abeboxclient .

After the building procedure, you can run the Docker container by executing the following command
> docker run -ti --privileged abeboxclient

## Run
Before running ABEBox Client, you should create a local directory where the Client will temporary store data in clear 
form, before protect and save it inside the destination directory.

Next you have to generate ABE keys locally running the following command
> python3 create_abe_msk.py -y

Finally, you can now start the ABEBox Client by simply running the following command
> python3 abebox.py basedir mountdir

where *basedir* is the destination folder where protected data is stored and *mountdir* is the previously created folder
with temporary data in clear form (the Docker container automatically creates them).

To test the Client, you need to use two shell windows because when you run the command the current shell will remain 
pending.

## Issues
To stop ABEBox Client, you just need to press *Ctrl+C*. If any error occurs during next executions, you may have to 
delete *mountdir* folder. If this operation is not possible, try to execute
> fusermount -u mountdir


[charm]: https://github.com/JHUISI/charm