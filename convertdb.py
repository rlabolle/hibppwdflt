#!/bin/env python
import sys
from array import array

def convert(source, dest):
    with open(source, 'r') as fp:
        with open(dest, 'wb') as db:
            print(f"Converting {source} to {dest}... ", end="")
            idx = array('I')
            idx.append(0)
            lastprefix = 0
            count = 0
            db.seek(idx.itemsize*(1<<24))
            for cnt, line in enumerate(fp):
                prefix = int(line[0:6],16)
                suffix = bytes.fromhex(line[6:32])
                while prefix != lastprefix:
                    idx.append(count)
                    lastprefix += 1
                    if lastprefix & 0xFF == 0:
                        print(f'{100*lastprefix/0xFFFFFF:6.2f} %',end="\b\b\b\b\b\b\b\b")
                db.write(suffix)
                count+=1
            while lastprefix != 0xFFFFFF:
                idx.append(count)
                lastprefix += 1
                if lastprefix & 0xFF == 0:
                    print(f'{100*lastprefix/0xFFFFFF:6.2f} %',end="\b\b\b\b\b\b\b\b")
            idx[0]=count
            db.seek(0)
            idx.tofile(db)
            print()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} source destination")
    else:
        convert(sys.argv[1], sys.argv[2])
