# PythonSTIGScan
Python script that imports STIG XML and compares it against a Cisco IOS config file for offline scanning

## Usage
This script is intended to be used automatically within a pipeline, but can be triggered manually via CLI if needed.
Basic usage is as follows:

If you are loading the STIG XML file for the first time, use the following command.
```
py -3 scanner.py --xml XMLFile
```
This will load the XML into the script and convert it to JSON, which is the format used by the script.

If the STIG XML file is already loaded and converted, you will need to load the config file from the network device.
```
py -3 scanner.py --config CONFIGFILE
```
This will load the file and kick the scan off.
Wait a little bit and the script should print the result to the terminal.
