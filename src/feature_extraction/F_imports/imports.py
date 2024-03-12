from src.feature_extraction import config
import os
import pefile


def padDlls(dlls, topDlls):
    # Take only those that are in the top DLLs
    consideredDlls = set(dlls) & topDlls
    # Put all dlls to false and mark true only those intersected
    extractedDlls = dict.fromkeys(topDlls, False)
    for consideredDll in consideredDlls:
        extractedDlls[consideredDll] = True
    return extractedDlls


def padImports(imps, topImports):
    # Take only those that are in the top Imports
    consideredImports = set(imps) & topImports
    # Put all imports to false and mark true only those intersected
    extractedImports = dict.fromkeys(topImports, False)
    for consideredImport in consideredImports:
        extractedImports[consideredImport] = True
    return extractedImports


def extract(sha1_family):
    sha1, family = sha1_family
    if family:
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
    else:
        filepath = os.path.join(config.GOODWARE_DIRECTORY, sha1)

    try:
        pe = pefile.PE(filepath)

        if pe.FILE_HEADER.Machine != 332:
            return {sha1: {'dlls': [], 'imps': [], 'error': 'File Header != 332'}}

        dlls = []
        imps = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode().lower()
                if not dll.endswith('.dll'):
                    # print("warning: {}".format(dll))
                    dll = "{}.dll".format(dll.split('.dll')[0])
                dlls.append(dll)
                for imp in entry.imports:
                    imp = imp.name
                    if imp:
                        imp = imp.decode().lower()
                        imp = 'imp_{}'.format(imp)
                        imps.append(imp)
        return {sha1: {'dlls': dlls, 'imps': imps, 'error': ''}}

    except pefile.PEFormatError as e:
        return {sha1: {'dlls': [], 'imps': [], 'error': e}}


def extractAndPad(filepath, topDlls, topImports):
    pe = pefile.PE(filepath)
    if pe.FILE_HEADER.Machine != 332:
        raise ValueError('File header machine != 332')

    dlls = []
    imps = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            if not dll.endswith('.dll'):
                # print("warning: {}".format(dll))
                dll = "{}.dll".format(dll.split('.dll')[0])
            dlls.append(dll)
            for imp in entry.imports:
                imp = imp.name
                if imp:
                    imp = imp.decode().lower()
                    imp = 'imp_{}'.format(imp)
                    imps.append(imp)
    return padDlls(dlls, topDlls), padImports(imps, topImports)
