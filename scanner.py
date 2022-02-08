import os
from glob import glob

import json
# import yaml

import sys
import argparse
import xmltodict
from ciscoconfparse import CiscoConfParse

def convertArgs():
    
    # Import STIG file to convert to JSON (GLOBAL ARGUMENT)
    parser_convert = argparse.ArgumentParser()
    subparser_convert = parser_convert.add_subparsers(help='Select the file type to convert')
    parser_convert.add_argument('--convert', '-c', metavar='convert', action='store_true', help='Converts STIG XML file to JSON')
    subparser_convert.add_subparsers('convert_file', help='Location of XML to Convert')
    subparser_convert.add_subparsers('out_JSON', help='Location of output JSON file')
    
    # Return --help if no arguments are given
    if len(sys.argv) <= 1:
        sys.argv.append('--help')
    
    return parser_convert.parse_args()

def importArgs(parser_convert):
    
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    
    parser.add_argument('--import', '-i', help='Point to locations for files to parse against')
    subparsers.add_parser('config_file', type=str, help='Location of Config file')
    subparsers.add_parser('json_file', type=str, default=parser_convert.out_JSON, help='Location of JSON file')
    
    args = parser.parse_args()
    return args
    
def XML2JSON(parser_convert):
    with open(parser_convert.xml_file) as xml_file:
        data_dict = xmltodict.parse(xml_file.read())
        xml_file.close()
        
        json_data = json.dumps(data_dict)
        
        with open("data_dict", "w") as json_file:
            json_file.write(json_data)
            json_file.close()

def main(parser_convert, args):
    
    # Convert XML if needed
    parser_convert.parse_args()
    convert_args = parser_convert.parse_args()
    
    # Load the Config file
    parse = CiscoConfParse(args.config_file)
    
    # Check which JSON file to load and load it
    with open(args.json_file, "r") as lj:
        loaded_JSON = json.load(lj)
    
    fail_count = 0
    # Iterative logic goes here -------------------------
    
    # Parse information from Config and print to terminal
    intobj = parse.find_objects(r"^interface")
    for obj in intobj:
        print(obj.text)
    
    sys.exit(fail_count)
    
if __name__ == '__main__':
    main()