from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)
from features_extraction.config.config import config
import os
import pefile


class ImportsExtractor(StaticFeatureExtractor):
    def extract(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.malware_directory_path, family, sha1)
        try:
            pe = pefile.PE(filepath)
            dlls = []
            imps = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode().lower()
                    if not dll.endswith(".dll"):
                        # print("warning: {}".format(dll))
                        dll = "{}.dll".format(dll.split(".dll")[0])
                    dlls.append(dll)
                    for imp in entry.imports:
                        imp = imp.name
                        if imp:
                            imp = imp.decode().lower()
                            imp = "imp_{}".format(imp)
                            imps.append(imp)
            return {sha1: {"dlls": dlls, "imps": imps, "error": ""}}
        except Exception as e:
            print(f"{sha1} {e}")
            return {sha1: {"dlls": [], "imps": [], "error": "error"}}

    def extract_and_pad(self, args):
        filepath, top_dlls, top_imports = args
        pe = pefile.PE(filepath)
        dlls = []
        imps = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode().lower()
                if not dll.endswith(".dll"):
                    # print("warning: {}".format(dll))
                    dll = "{}.dll".format(dll.split(".dll")[0])
                dlls.append(dll)
                for imp in entry.imports:
                    imp = imp.name
                    if imp:
                        imp = imp.decode().lower()
                        imp = "imp_{}".format(imp)
                        imps.append(imp)
        return self.__pad_dlls(dlls, top_dlls), self.__pad_imports(imps, top_imports)

    @staticmethod
    def __pad_dlls(dlls, top_dlls):
        # Take only those that are in the top DLLs
        considered_dlls = set(dlls) & top_dlls
        # Put all dlls to false and mark true only those intersected
        extracted_dlls = dict.fromkeys(top_dlls, False)
        for consideredDll in considered_dlls:
            extracted_dlls[consideredDll] = True
        return extracted_dlls

    @staticmethod
    def __pad_imports(imps, top_imports):
        # Take only those that are in the top Imports
        considered_imports = set(imps) & top_imports
        # Put all imports to false and mark true only those intersected
        extracted_imports = dict.fromkeys(top_imports, False)
        for considered_import in considered_imports:
            extracted_imports[considered_import] = True
        return extracted_imports
