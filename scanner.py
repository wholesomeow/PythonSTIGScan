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
        clean_subkeys = ['Severity', 'Explaination', 'Fix_Action', 'Enable', 'Command_Block', 'Fail_Value']
        clean_data = []
        result_data = []
        
        # Parse Information from data.json and append it to new json file
        with open('data.json', 'r') as data_json:
            data = json.load(data_json)
            print('Cleaning JSON data')
            
            for group in data:
                group = data['Benchmark']['Group']
                
                # Find Vulnerability ID, Severity, Explaination, and Fix Action
                for item in group:
                    clean_subdata = []
                    result_subdata = []
                    clean_subdata.append(item['Rule']['@severity'])
                    clean_subdata.append(item['Rule']['title'])
                    clean_subdata.append(item['Rule']['fixtext']['#text'] + '\n\n')
                    
                    # Enable Bool Assignment
                    action = item['Rule']['fixtext']['#text']
                    if re.search('Configure', action):
                        res = True                       
                    elif re.search('Disable', action):
                        res = False
                    clean_subdata.append(res)
                    
                    # Value that contains specific commands to parse against config
                    paction = re.findall(r'\((.*)', action)
                    clean_subdata.append(paction)
                    
                    # Value that returns points for each section of each vulnerability - points earned on failure
                    severity = item['Rule']['@severity']
                    if severity == 'high':
                        value = 15
                    elif severity == 'low':
                        value = 5
                    else:
                        value = 10
                    clean_subdata.append(value)
                    
                    clean_data.append(item['@id'])
                    clean_data.append(result_subdata)

            # Combine Data and Keys to list                    
                    n = len(clean_subdata)
                    for idx in range(0, n, 6):
                        result_subdata.append({clean_subkeys[0] : clean_subdata[idx],
                                            clean_subkeys[1] : clean_subdata[idx + 1],
                                            clean_subkeys[2] : clean_subdata[idx + 2],
                                            clean_subkeys[3] : clean_subdata[idx + 3],
                                            clean_subkeys[4] : clean_subdata[idx + 4],
                                            clean_subkeys[5] : clean_subdata[idx + 5]
                                            })                    
            n = len(clean_data)
            for idx in range(0, n, 2):
                result_data.append({clean_keys[0] : clean_data[idx],
                                    clean_keys[1] : clean_data[idx + 1]
                                    })               
            data_json.close()
            
        # Write list to new json        
        clean_json = json.dumps(result_data, indent=4, sort_keys=False)
        with open('clean_data.json', 'w') as cleandata:
            cleandata.write(clean_json)
            cleandata.close()            
            
        with open('clean_data.json', 'r') as cleandata:
            data = json.load(cleandata)
            print('Creating additional data')
            
        # Populate Enable field in clean_data.json
            
        # Populate Fail Value field in clean_data.json
        
        # Populate Command Block field in clean_data.json
                
                
            cleandata.close()

def main():
    
    # Process Arguments
    args = importArgs()
    print('Consuming Arguments')
    
    # Convert XML and load the JSON file    
    if args.xml != None:
        print('Ingesting XML')
        with open(args.xml) as xml_file:
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            
            json_data = json.dumps(data_dict, indent=4, sort_keys=True)
            
            with open("data.json", "w") as json_file:
                json_file.write(json_data)
                json_file.close()
            print('Writing XML to JSON')
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
    
    print('Complete')
    sys.exit(fail_count)
    
if __name__ == '__main__':
    main()