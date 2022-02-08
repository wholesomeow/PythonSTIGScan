# PythonSTIGScan
Python script that imports STIG XML and compares it against a Cisco IOS config file for offline scanning

## Usage
This script is intended to be used automatically within a pipeline, but can be triggered manually via CLI if needed.
Basic usage is as follows:
```
py -3 scanner.py ConfigFile STIGFile
```
This triggers the script with the IOS configuration file with the STIG JSON file following it.
For ease of use, they should be placed within the same directory as the script, but standard file locations can work.

Importing the STIG file is simple, but the default file type is XML not JSON.
This isn't a problem, as with the following argument the XML can be converted into JSON and loaded the same way.
```
py -3 scanner.py --convert XMLFile JSONOutput
```
Here the JSONOutput will be the name and locaiton of the name of the converted JSON file.