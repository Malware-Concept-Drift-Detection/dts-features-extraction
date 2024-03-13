import os
from src.feature_extraction import config
import subprocess


def extract(sha1_family):
    sha1, family = sha1_family
    if family:
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
    else:
        filepath = os.path.join(config.GOODWARE_DIRECTORY, sha1)
    cmd = ['strings', filepath]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode("utf-8")
    strings = output.split('\n')
    strings = [string.strip() for string in strings]
    strings = [string for string in strings if len(string) > 3]
    return strings


def pad_strings(strings, top_strings):
    # Take only those that are in the top Strings
    considered_strings = strings & top_strings

    # Put all Strings to false and mark true only those intersected
    extracted_strings = dict.fromkeys(top_strings, False)
    for considered_string in considered_strings:
        extracted_strings[considered_string] = True
    return extracted_strings


def extract_and_pad(filepath, top_strings):
    cmd = ['strings', filepath]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode("utf-8")
    strings = output.split('\n')
    strings = [string.strip() for string in strings]
    strings = [string for string in strings if len(string) > 3]
    return pad_strings(set(["str_" + s for s in strings]), top_strings)
