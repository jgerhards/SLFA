# How to anonymize a log file

To anonymize data with SLFA you need three files:
1. the programm as a jar file (here: SLFA.jar)
2. the configuration file (here: config.txt)
3. the file to be anonymized (here: access.log)

## The Jar File

The Jar file contains the program. To run it you will need to install Java, if you not already have it.

## The Configuration File

For SLFA to know how to anonymize your file you need to specify the details in the configuration file. Here is an example for an configuration file, which we will use.

'''
anonymizer=ipv4, ipv6

ipv4.bits=32

ipv4.mode=zero

ipv6.bits=112

ipv6.mode=zero
'''

The configuration begins always with the specification of the used anonymizers. This is done using the parameter 'anonymizer'. In this example we are using ipv4 and ipv6 anonymizer.

After that the single anonymizer are configured. This is done in the following format: '<anonymizerName>.<parameterName>=<value>'.

## Running the program

When you have all three files you can start the program in the command line with the following command:

'''
java -Dconfigfile=PATH\TO\CONFIG\FILE -jar slfa.jar FILENAMES
'''

The configuration file is set with the parameter '-Dconfigfile'. Then you set the jar file with parameter '-jar', followed by first the jar file and then the names of all files to be anonymised.
The anonymized file will be forwarded to stdout so it is recommended to redirect it to a file.
In our example the command would look like this:

'''
java -Dconfigfile=config.txt -jar SLFA.jar access.log > output.log
'''

Like this you will have your anonymized version of access.log in output.log.

Slfa also allows to read from standard input:
```
cat access.log | java -Dstdin -Dconfigfile=PATH_TO_CONFIG_FILE -jar SLFA.jar
```

You can execute the following commands to get started with Slfa and to anonymize some logfile:
```
# Download and create jar
git clone https://github.com/jgerhards/SLFA.git
cd SLFA
gradle jar

# Example for a plaintext file - using file parameter
java -Dstdin -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/SLFA.jar "/var/log/apache2/access.log"  > anon.log
# Example for a plaintext file - using stdin
cat "/var/log/apache2/access.log"  |  java -Dstdin -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/SLFA.jar > anon.log
# Example for a packed file
zcat "/var/log/apache2/access.log.2.gz"  |  java -Dstdin -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/SLFA.jar > anon.log
```
