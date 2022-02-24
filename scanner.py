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
    group.add_argument('--start',
                       type=str,
                       help='Use once XML and STIG have been loaded into the script to being the scan')
    

    return parser.parse_args()

def convertJSON():
    # Create Convertion Loop Variables
        clean_keys = ['ID', 'Rule']
        clean_subkeys = ['Severity', 'Explaination', 'Fix_Action', 'Enable', 'Command_Block', 'Fail_Value', 'Global']
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
                    
                    # Global Check
                    raction = re.findall(r'#int', action)
                    gvar = 0
                    if raction:
                        gvar += 1
                    else:
                        gvar += 0
    
                    if gvar == 0:
                        clean_subdata.append(True)
                    elif gvar > 0:
                        clean_subdata.append(False)
                    else:
                        print('ERROR: Global Check Failed')
                    
                    clean_data.append(item['@id'])
                    clean_data.append(result_subdata)

            # Combine Data and Keys to list                    
                    n = len(clean_subdata)
                    for idx in range(0, n, 7):
                        result_subdata.append({clean_subkeys[0] : clean_subdata[idx],
                                            clean_subkeys[1] : clean_subdata[idx + 1],
                                            clean_subkeys[2] : clean_subdata[idx + 2],
                                            clean_subkeys[3] : clean_subdata[idx + 3],
                                            clean_subkeys[4] : clean_subdata[idx + 4],
                                            clean_subkeys[5] : clean_subdata[idx + 5],
                                            clean_subkeys[6] : clean_subdata[idx + 6]
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

def scanBegin():
    
    # TEMP: Import args to parse config
    parse = CiscoConfParse('IOS_XE_PreSTIG.conf')
        
    # TEMP: Pull Global Vuln from clean_data.json
    with open('clean_data.json', 'r') as data_json:
        data = json.load(data_json)
        print('Starting Scan')
        print('TEMP: Pulling Global vulnerabilities only')
        
        i = 0
        r = len(data)
        for i in range(0, r, 1):
            rule = data[i]['Rule'][0]['Global']
            cmd = data[i]['Rule'][0]['Command_Block']
            vuln = data[i]['ID']
            fval = data[i]['Rule'][0]['Fail_Value']
            if rule == True or (rule == True and cmd == ''):
                
                # Logic for scanning starts here
                idx = 0
                for idx in range(0, len(cmd), 1):
                    curcmd = cmd[idx]
                    
                    curvuln = re.findall(r'-(.*)', str(vuln))
                    cleanparse = re.findall(r'#(.*)', str(curcmd))
                    
                    # Escape special characters in cleanparse
                    splist = list(str(cleanparse))
                    for i in range(0, len(splist), 1):
                        if i == '-':
                            loc = splist.index('-')
                            splist.insert(loc - 1, '\\')
                        else:
                            continue
                    cparse = ''
                    cparse.join(splist)
                    
                    # CCP Parse Logic
                    for obj in parse.find_objects(str(cparse)):
                        if obj == True:
                            continue
                        elif obj != True:
                            # TODO: Turn this into a result.json
                            # TODO: Also, make this only scan global vulnerabilities - it's currently not
                            print(str(curvuln))
                            print(str(cleanparse))
                            print(int(fval))
                            break
                        else:
                            print('ERROR: Failed to properly parse config')
                    idx += 1
            else:
                continue
            i += 1
        print('Scan Complete')
        data_json.close()
                

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
        
        #Clean old files
        print('Cleaning old files')
        os.remove('data.json')
                                 
    elif configLoaded:
        print('Configuration Loaded. Good to being scan')
        scanReady = True
        
    scanBegin()
    
    print('Complete')
    sys.exit(fail_count)
    
if __name__ == '__main__':
    main()