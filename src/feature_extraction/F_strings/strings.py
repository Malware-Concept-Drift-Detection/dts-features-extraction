#!/usr/bin/env python3
import os
import config
import subprocess
import sys

def extract(sha1_family):
    sha1,family = sha1_family
    if family:
        filepath = os.path.join(config.MALWARE_DIRECTORY,family,sha1)
    else:
        filepath = os.path.join(config.GOODWARE_DIRECTORY,sha1)
    cmd = ['strings', filepath]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode("utf-8")
    strings = output.split('\n')
    strings = [string.strip() for string in strings]
    strings = [string for string in strings if len(string)>3]
    return strings

def padStrings(strings,topStrings):
    #Take only those that are in the top Strings
    consideredStrings = strings & topStrings

    #Put all Strings to false and mark true only those intersected
    extractedStrings = dict.fromkeys(topStrings,False)
    for consideredString in consideredStrings:
        extractedStrings[consideredString] = True
    return extractedStrings

def extractAndPad(filepath,topStrings):
    cmd = ['strings', filepath]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode("utf-8")
    strings = output.split('\n')
    strings = [string.strip() for string in strings]
    strings = [string for string in strings if len(string)>3]
    return padStrings(set(["str_"+s for s in strings]),topStrings)
