from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import os
import pefile


class ImportsExtractor(StaticFeatureExtractor):

    def __init__(self):
        self.sha_exclude = [
            "f74fd4a5b4428aae71cc7e6ca79379e9d11da7b69702997d8666437362258c40",
            "dfa577d4b4f2d03231304711783f56059e49225c66c36a1fdd45d3234d4448f9",
            "d0e633203dca149fb61288f02f2225aab8d4d8058bd78dfc5e7a5c117213a57a",
            "351cd8d7048ce371d1f37e5eb12682ca395dee89fdd41b4cbea22cdf172fd768"
        ]

    def extract(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        if sha1 not in self.sha_exclude:
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
            # except:
            #     print(filepath)
            except:
                print(filepath)
                return {sha1: {'dlls': [], 'imps': [], 'error': "error"}}
        return {sha1: {'dlls': [], 'imps': [], 'error': "error"}}

    def extract_and_pad(self, args):
        filepath, top_dlls, top_imports = args
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
        return self.__pad_dlls(top_dlls), self.__pad_imports(top_imports)

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
