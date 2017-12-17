#!/usr/bin/env python3

import csv

from phe import paillier

from keys import pk_from_file


def read_csv_database(filename, public_key, is_encrypted=True):
    """Generate an encrypted database from a CSV."""
    database = []
    row_len = 0

    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)

        for row in reader:
            if not row_len:
                row_len = len(row)
            elif len(row) != row_len:
                raise RuntimeError("Uneven csv, lengths {} and {}".format(len(row), row_len))

            db_row = []
            for cell_val in map(int, row):

                if is_encrypted:
                    enc_val = paillier.EncryptedNumber(public_key, cell_val)
                else:
                    enc_val = public_key.encrypt(cell_val)

                db_row.append(enc_val)

            database.append(tuple(db_row))

    return tuple(database)


def write_csv_database(filename, database):

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        for row in database:
            ciphertext_row = (cell.ciphertext() for cell in row)
            writer.writerow(ciphertext_row)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Paillier encryption of "
                                     "CSV databases.")
    parser.add_argument('--csv', help="Unencrypted CSV database to read.")
    parser.add_argument('--key', type=argparse.FileType(), help="Key to "
                        "encrypt the database with.")
    parser.add_argument('--name', help="Base file name for the output file.")

    ARGS = parser.parse_args()
    csvfilename = ARGS.csv
    keyfile = ARGS.key
    name = ARGS.name

    key = None

    if keyfile:
        key = pk_from_file(keyfile)
    else:
        keyfilename = input("Please enter the encryption key's file name: ")
        with open(keyfilename, 'r') as okeyfile:
            key = pk_from_file(okeyfile)

    if not name:
        name = input('Please enter the base file name to output to: ')
    if name.lower().endswith('.csv'):
        name = name[:-4]

    if not csvfilename:
        csvfilename = input('Please enter the filename of T, the unencrypted '
                            'CSV database: ')

    enc_database = read_csv_database(csvfilename, key, False)
    output_name = '{}.enc.csv'.format(name)

    write_csv_database(output_name, enc_database)

    print("Successfully wrote encrypted database to {!r}".format(output_name))
