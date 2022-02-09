import os
from glob import glob

import json
# import yaml

import sys
import argparse
import xmltodict
from ciscoconfparse import CiscoConfParse

def importArgs():
    
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--config', 
                        type=str, 
                        help='Point to locations for files to parse against')
    group.add_argument('--xml', 
                        type=str, 
                        help='Converts STIG XML file to JSON')

    return parser.parse_args()
    
def main():
    
    # Process Arguments
    args = importArgs()
    
    # Convert XML and load the JSON file    
    if args.xml != None:
        with open(args.xml) as xml_file:
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            
            json_data = json.dumps(data_dict, indent=4, sort_keys=True)
            
            with open("data.json", "w") as json_file:
                json_file.write(json_data)
                json_file.close()
            
    # Load the Config file           
    elif args.config != None:
        parse = CiscoConfParse(args.config_file)
    else:
        print("Argument Processing Failed")

    fail_count = 0
    # Iterative logic goes here -------------------------
    
    # Parse information from Config and print to terminal
    intobj = parse.find_objects(r"^interface")
    for obj in intobj:
        print(obj.text)
    
    sys.exit(fail_count)
    
if __name__ == '__main__':
    main()