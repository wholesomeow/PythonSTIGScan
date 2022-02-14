import os
from glob import glob

import json
# import yaml

import re
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

def convertJSON():
    # Create Convertion Loop Variables
        clean_keys = ['ID', 'Rule']
        clean_subkeys = ['Severity', 'Explaination', 'Fix_Action']
        clean_data = []
        result_data = []
        
        # Parse Information from data.json and append it to new json file
        with open('data.json', 'r') as data_json:
            data = json.load(data_json)
            
            for group in data:
                group = data['Benchmark']['Group']
                
                # Find Vulnerability ID, Severity, Explaination, and Fix Action
                for item in group:
                    clean_subdata = []
                    result_subdata = []
                    clean_subdata.append(item['Rule']['@severity'])
                    clean_subdata.append(item['Rule']['title'])
                    clean_subdata.append(item['Rule']['fixtext']['#text'])

                    clean_data.append(item['@id'])
                    clean_data.append(result_subdata)

            # Combine Data and Keys to list                    
                    n = len(clean_subdata)
                    for idx in range(0, n, 3):
                        result_subdata.append({clean_subkeys[0] : clean_subdata[idx],
                                            clean_subkeys[1] : clean_subdata[idx + 1],
                                            clean_subkeys[2] : clean_subdata[idx + 2]
                                            })                    
            n = len(clean_data)
            for idx in range(0, n, 2):
                result_data.append({clean_keys[0] : clean_data[idx],
                                    clean_keys[1] : clean_data[idx + 1]
                                    })               
            data_json.close()
            
        # Write list to new json        
        clean_json = json.dumps(result_data, indent=4, sort_keys=True)
        with open('clean_data.json', 'w') as cleandata:
            cleandata.write(clean_json)
            cleandata.close()
    
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
        converted = True
        
    # Load the Config file           
    elif args.config != None:
        parse = CiscoConfParse(args.config_file)
        
        configLoaded = True
        
    else:
        print("Argument Processing Failed")

    # Iterative logic goes here -------------------------
    
    fail_count = 0
    if converted:
        convertJSON()
        # Parse Fix Action        
        with open('clean_data.json', 'r') as cleandata:
            data = json.load(cleandata)

            i = 0
            for fix in data:
                fix = data[i]['Rule'][0]['Fix_Action']
                i += 1
        
            cleandata.close()                           
    elif configLoaded:
        print(None)
    
    sys.exit(fail_count)
    
if __name__ == '__main__':
    main()