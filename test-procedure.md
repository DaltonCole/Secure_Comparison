
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
