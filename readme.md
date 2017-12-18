# Secure Comparison

This project is a python3 implementation of the paper [Secure k-Nearest Neighbor Query over Encrypted Data in Outsourced Environments](http://web.mst.edu/~wjiang/SkNN-ICDE14.pdf).

### Installation
All code is written in python3. The dependencies can be installed using
```
pip install phe
```
### Usage
Communication between the parties is networked on localhost. The server and client must each be run independently to start a session.
In one terminal, type
```
./server.py
```
In a second terminal, type
```
./client.py
```
After running [key generation](#Key_Generation) you will be asked for a [functionality](#Functions) to perform.

### Server
The server represents P1 (or Bob for SkNN)
```
usage: server.py [-h] [port]

positional arguments:
  port        port to listen on (default: 49556)

optional arguments:
  -h, --help  show this help message and exit
```


### Client
The client represents P2 (or C1/C2 for SkNN)
```
usage: client.py [-h] [-s SK] [-o OPT] [port]

positional arguments:
  port                  port to connect to (default: 49556)

optional arguments:
  -h, --help            show this help message and exit
  -s SK, --secret-key SK
                        pregenerated secret key. If omitted we will generate a
                        key pair.
  -o OPT, --option OPT  the option to execute. Start interactively to see
                        available options
```


### Key Generation
Keys can manually be generated by running `./keys.py`. Alternatively, this will
automatically be performed when a session is created between the server and client.
```
optional arguments:
  -h, --help   show this help message and exit
  --name NAME  Base file name for the output files.
  -p, --pq     Generate from p and q values.
  -b, --bit    Generate by bit-length.
```
Example:
```
./keys.py --name example -b
```

### Functions
1. [Secure Multiplication](#SM)
2. [Secure Minimum](#SMIN)
3. [Secure Squared Euclidian Distance](#SSED)
4. [Secure Bit Decomposition](#SBD)
5. [Secure Bit-OR](#SBOR)
6. [Secure Minimum-of-n](#SMIN-of-n)
7. [Secure k-Nearest Neighbors](#SkNN)


## SkNN

### Requirements
 * Three terminals: **Bob**, **C1**, **C2**
 * The database, a CSV file of integers

### Procedure
 * **C2**:
    * Run `./keys.py --name testk` to interactively generate a Paillier key pair
      `testk.private.json` and `testk.public.json`.
    * Run `./database.py --name testdb --key testk.public.json` to encrypt your
      database into `testdb.enc.csv`; make this accessible to **C1**.
 * **Bob**:
    * Run `./server.py` to start the server.
 * **C2**:
    * Run `./client.py -s testk.private.json -o c2` to start client C2.
 * **C1**:
    * Run `./client.py 49557 -o c1` to start client C1.
 * **Bob**:
    * Enter your query _Q_, a set of space-separated values, the same width as
      a database row.
    * Enter _k_, the number of results.
 * **C1**:
    * Enter the database name `testdb.enc.csv`
 * **Bob**:
    * Choose the output method for the result. `p` to print, `c` for CSV.
