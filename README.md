Feature-extraction
===
This repository contains scripts to extract features from Android APKs, required for the [machine learning process to detect malware](https://github.com/33onethird/malware-test)

Requirements
---
The central component used to extract features from an app is the FeatureExtractor.jar file. 
The program uses [apktool.jar](https://ibotpeaches.github.io/Apktool/) in its working directory to unzip the app and decompile the code. 
We also use LibScout (https://github.com/reddr/LibScout). The compiled LibScout.jar, [android-x.jar](https://github.com/reddr/LibScout/tree/master/lib) as well as the logging folder (provided here) and the profiles folder from https://github.com/reddr/LibScout-Profiles must be present in the working directory.

Both programs are written in Java and thereby require a Java Runtime Environment (8 or higher) installed. 

In addition to the apktool, the FeatureExtractor requires the files apicalls_suspicious.txt and jellybean_allmappings.txt to be present in 
the working directory. 
#### apicalls_suspicious.txt
contains suspicious api calls used by malware. obtained from the team of the original DREBIN paper.

#### jellybean_allmappings.txt 
contains the information which call requires which permission(s) from the Android operating system.
[Original Download](http://pscout.csl.toronto.edu/data/old/jellybean_allmappings.txt)

Both are available in this repository.

Setup
---
To install the requirements on Ubuntu:

```sudo apt-get install openjdk-8-jre icedtea-8-plugin```

To use the feature extractor, call

```java -jar FeatureExtractor.jar [inputDir] [outputDir]```

where `outputDir` and `inputDir` are directories and `inputDir` contains the apps.

Workflow
---
First of all, the files apicalls_suspicious.txt and jellybean_allmappings.txt are loaded and stored in data structures. The program iterates through all files in the inputDir and processes them sequentially. Every file is unpacked and decompiled using apktool.jar, which creates a folder containing the unpacked app in the working directory. This folder is deleted after the analysis. If the unpacking process takes more than 30 seconds, the process is aborted and the app will be skipped. This is necessary, because one corrupt file could prevent the analysis of all other apps in the directory.

Afterwards, the program parses AndroidManifest.xml. The .xml file contains information such as requested permissions, activity names and intent-filters. Everything extracted from this file and written to the output can be directly found in the manifest. There is no data manipulation/transformation in this part. In particular, the following tags are extracted from this file: activity, permission, feature, intent, service_receiver  



The second source of information is the decompiled code (.smali files). The URLs accessed by the app can be foundhere by using a regular expression, which matches every string starting with "http://" or "https://". The call tag can be extracted by checking whether a line of decompiled code contains a line from apicalls_suspicious.txt. If a line contains "Cipher" the previous line of code is also analyzed in order to determine the exact method of encryption (e.g. Cipher(AES/CBC/PKCS5Padding)). The information from jellybean_allmappings.txt is used to extract all calls present in the decompiled code and the mapping file. In a second step, all by method calls required permissions are determined using jellybean_allmappings.txt. These are the permissions actually required by the program. The permissions requested in AndroidManifest.xml CAN be used, but it is not a necessity to use all of them. The following tags are extracted from the decompiled code: api_call, permission, url, call, real_permission  
