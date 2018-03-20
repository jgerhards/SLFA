# slfa

Slfa stands for "simple log file anonymizer" where "simple" stands for easy of use, not
missing features. It is a command line tool capable of anonymizing different data types in files:

* IPv4 adresses
* IPv6 addresses
* any data that can be described by a regular expression

Slfa not only supports anonymization but also pseudonymization. The is especially useful when a data set shall be
used to train analyzers or normalization tools.

Slfa was begun in summer 2017 and will continously be extended. The project was initiated by [Jan Gerhards](http://jan.gerhards.net).

## starting slfa
When starting the programm on the command line, it should look like this:
```
java -Dconfigfile=PATH_TO_CONFIG_FILE -jar slfa.jar FILENAMES
```
Most of the configuration of slfa works via a configuration file. The path to this file is read out of the environment variable LOGANONYMIZER_CONFIG. Alternatively, you can set the file to read the configuration out of by using the -Dconfigfile parameter (overrides environment variable if it is set). For this parameter, it is important to remember to give not only the filename, but the whole path to guarantee the programm finding the file. 
Following the starting command itself are the names of files to be anonymized. Slfa will go through each of the files in the order provided and anonymize depending on the configuration. The output will be given to stdout, meaning the anonymized content of the files will appear in the terminal.

Slfa also allows to read from standard input:
```
zcat access.log.2.gz | java -Dstdin -Dconfigfile=PATH_TO_CONFIG_FILE -jar slfa.jar
```


You can execute the following commands to get started with Slfa and to anonymize some logfile:
```
# Download and create jar
git clone https://github.com/jgerhards/SLFA.git
cd SLFA
gradle jar

# Example for a plaintext file - using file parameter
java -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/slfa.jar "/var/log/apache2/access.log"  > anon.log
# Example for a plaintext file - using stdin
cat "/var/log/apache2/access.log" | java -Dstdin -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/slfa.jar > anon.log
# Example for a packed file
zcat "/var/log/apache2/access.log.2.gz" | java -Dstdin -Dconfigfile=conf/example-slfa-all-ip-half.properties -jar build/libs/slfa.jar > anon.log
```


## configuration file
All the configuration parameters in the configuration file are structured like this:
```
example.config=123
another.example=word
```
They each stand in a new line and are composed by the parameter name, followed by a '=' and the value which the parameter should represent. 
Please note that because of the framework the characters ';' and '\\' will be escaped and you will have to put another '\\' in front of it. For example, to set "\\." as a parameter, you have to write "\\\\." in the configuration file.

The configuration file has many different parameters, but the most important one is ```anonymizer```.
It specifies which anonymizers are applied to the file as well as in what order. However, it does not influence the configuration of the anonymizers temselves. This happens in a separate part for every anonymizer listed in this parameter. The format of this parameter calls for every anonymizer to be separated by a space. No other character may be used, except for commas, which may only be used if not separated by a space and if the anonymizers still have at least one space between them (example: ipv6, ipv4). In cases where more than one anonymizer of the same type (currently only supported by the regex anonymizer) is to be used, they also have to be diffentiated by a number. This number has to be separated by a space from the type and no other charakters may be inbetween the number and the type. It does not matter what number is used. They do not have to be in order and if more than one type of anonymizer is classified by a number, it will work, as long as no number is used twice in a type. Please keep in mind that a number has to be used, even if it is the only anonymizer of that type.


### IPv4 anonymizer
We assume that an IPv4 address consists of four octets in dotted notation, where each of the octets has a value between 0 and 255, inclusively.
Every parameter regarding this anonymizer is formated like this: ```ipv4.NAME_OF_PARAMETER=VALUE_OF_PARAMETER```

#### Parameters
* **bits** - default 16
  
  number between 1 and 32
  This sets the number of bits that should be anonymized (bits are from the right, so lower bits are anonymized first). This setting permits to save network information while still anonymizing user-specific data. The more bits you discard, the better the anonymization obviously is. The default of 16 bits reflects what German data privacy rules consider as being sufficinetly anonymized. We assume, this can also be used as a rough but conservative guideline for other countries.

* **mode** - default zero

  "*zero*", "*random*" or "*random-consistent*"
  
  There exist the "random", "random-consitent", and "zero" modes. The modes "random" and "random-consistent" are very similar, in that they both anonymize ip-addresses by randomizing the last bits of a given address. However, while "random" mode assigns a new completely random ip-address for every address in a message, "random-consitent" will assign the same randomized address to every instance of the same original address.

  The default "zero" mode will do full anonymization of bits and it will also normalize the address, so that no information about the original IP address is available. So for example, 10.1.12.123 would be anonymized to 10.1.0.0 (with 16 bits).


### IPv6 anonymizer
An IPv6 is defined by being bewtween zero and eight hex values between 0 and ffff. These are separated by ':'. Leading zeros in blocks can be omitted and blocks full of zeros can be abbreviated by using '::'. However, this can ony happen once in an IP address.
Every parameter regarding this anonymizer is formated like this: ```ipv6.NAME_OF_PARAMETER=VALUE_OF_PARAMETER```

#### Parameters
* **bits** - default 96

  This sets the number of bits that should be anonymized (bits are from the right, so lower bits are anonymized first). This setting permits to save network information while still anonymizing user-specific data. The more bits you discard, the better the anonymization obviously is. The default of 96 bits reflects what German data privacy rules consider as being sufficinetly anonymized. We assume, this can also be used as a rough but conservative guideline for other countries.

* **mode** - default zero

  "zero", "random" or "random-consistent"
  
  This defines the mode, in which IPv6 addresses will be anonymized.
  There exist the "random", "random-consitent", and "zero" modes.

  The modes "random" and "random-consistent" are very similar, in that they both anonymize ip-addresses by randomizing the last bits (any number) of a given address. However, while "random" mode assigns a new completely random ip-address for every address in a message, "random-consitent" will assign the same randomized address to every instance of the same original address.

  The default "zero" mode will do full anonymization of any number of bits and it will also normalize the address, so that no information about the original IP address is available.
  Also note that an anonymmized IPv6 address will be normalized, meaning there will be no abbreviations, leading zeros will not be displayed, and capital letters in the hex numerals will be lowercase. So for example, 12F:3DE9::22:9A would be anonymized to 0:0:0:0:0:0:0:0 (with 128 bits).


### IPv6 with embedded IPv4 anonymizer
An IPv6 with embedded IPv4 is defined by being bewtween zero and six hex values between 0 and ffff. These are separated by ':'. Leading zeros in blocks can be omitted and blocks full of zeros can be abbreviated by using '::'. However, this can ony happen once in an IP address. This is followed by an IPv4 address (see IPv4 for definition) that is separated from the first part by a ':'. You can select this anonymization type by adding 'embeddedipv4' to the anonymizer configuraion.
Every parameter regarding this anonymizer is formated like this: ```embeddedipv4.NAME_OF_PARAMETER=VALUE_OF_PARAMETER```

#### Parameters
* **bits** - default 96

  This sets the number of bits that should be anonymized (bits are from the right, so lower bits are anonymized first). This setting permits to save network information while still anonymizing user-specific data. The more bits you discard, the better the anonymization obviously is. The default of 96 bits reflects what German data privacy rules consider as being sufficinetly anonymized. We assume, this can also be used as a rough but conservative guideline for other countries.

* **mode** - default zero

  "zero", "random" or "random-consistent"
  
  This defines the mode, in which IPv6 addresses will be anonymized.
  There exist the "random", "random-consitent", and "zero" modes.

  The modes "random" and "random-consistent" are very similar, in that they both anonymize ip-addresses by randomizing the last bits (any number) of a given address. However, while "random" mode assigns a new completely random ip-address for every address in a message, "random-consitent" will assign the same randomized address to every instance of the same original address.

  The default "zero" mode will do full anonymization of any number of bits and it will also normalize the address, so that no information about the original IP address is available.
  Also note that an anonymmized IPv6 address will be normalized, meaning there will be no abbreviations, leading zeros will not be displayed, and capital letters in the hex numerals will be lowercase. So for example, 12F:3DE9::22:172.1.1.0 would be anonymized to 0:0:0:0:0:0:0.0.0.0 (with 128 bits).


### Regex anonymizer
The regex anonymizer works with regular expressions. Since one might want to anonymize different regular expressions, it is possible to use multiple regex anonymizer. Because of this however, an auxiliary number has to be used with the regex anonymizer, even if only using one regex anonymizer.
Every parameter regarding an anonymizer of this type is formated like this: 
```
regex[NUMBER_OF_ANONYMIZER].NAME_OF_PARAMETER=VALUE_OF_PARAMETER
```

#### Parameters
* **in** - no default

  This parameter sets the regular expression to anonymize. Because of this, it is a neccessary parameter. If it is not set, the whole regex anonymizer will be ignored (only the instance lacking an in value, every other instance will work if configured correctly).

* **mode** - default random

  There are currently three modes available: the random, the random-consistent and
  the replace mode. in random mode, the found regex string will be replaced by random
  characters. What characters will be randomized can be further configured using the
  "keep" option.
  The random-consistent mode behaves very similarly to the random mode, but if it finds
  the same regex multiple times, it will always anonymize it to the same randomly
  generated string.
  In replace mode, the regex will be replaced by a string (see replace option).

* **keep** - default all off

  When using random mode, it is possible to only randomize certain types of characters. To achieve this you have to give the groups of characters you want to not be randomized as the parameter for the keep option. If you wish to include multiple groups you have to sparate each group name with a space.
  The first group of characters is every character with an ASCII value between 48 and 57 (inclusive). This group can be kept by adding "num" to the option. The second group consists of characters with an ASCII value between 65 and 90 and between 97 and 122. It is identified with the name "char". Any other character is included in the third group named "spchar".
  When operating in any other mode, this parameter gets ignored.

* **replace** - no default
  When using replace mode, the regex gets replaced by a given (static) string. This is where to set the string. When operating in any other mode, this parameter gets ignored.

### example
In this example, We want to anonymize IPv4 and IPv6 addresses. After that, we also want to anonymize any other hex value. Because of this, we have to first annymize the IP addresses and only after that the regex for hex values.
```
anonymizer=ipv4, ipv6, regex 1

regex[1].in=^#?([a-f0-9]{6}|[a-f0-9]{3})$
regex[1].mode=replace
regex[1].replace=<hex value>

ipv4.bits=32
ipv4.mode=zero

ipv6.bits=112
ipv6.mode=random-consistent
```

## Development
If you want to start contributing to slfa, you can work with any IDE.
* To prepare the project to be edited with Eclipse, you can prepare the project using `./gradlew eclipse`
* Same for IntelliJ, you can prepare the project using `./gradlew idea`
* Most likely you already have `gradle` installed on your system, then you can use that instead of gradlew.
