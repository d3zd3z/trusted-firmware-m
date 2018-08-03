#! /usr/bin/env python3

import argparse
import getopt
import sys

def main(argv):
    inputfile = ''
    data_size = 0
    ram_used = 0
    
    try:
        opts, args = getopt.getopt(argv,"hi:",["ifile="])
    except getopt.GetoptError:
        print('memory_usage.py -i <inputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('memory_usage.py -i <inputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
    print('TFM_S map file: ', inputfile)

    with open(inputfile, encoding="utf-8") as file:
        for line, string in enumerate(file):
            if string.find('Execution Region ER_TFM_DATA') >= 0:
                data_size = int(string.split()[8][0:-1], 16)
            elif string.find('Program Size:') == 0 or string.find(
                           'Total RO  Size') >= 0:
                print(string)
            elif string.find('Total RW  Size') >= 0:
                ram_used = int(string.split()[8])
                print(string)

    if data_size and ram_used:
        print('TFM RAM Size: %dKB %.1f%%Used' % ((data_size / 1024), (ram_used / data_size) *100))

if __name__ == "__main__":
    main(sys.argv[1:])
