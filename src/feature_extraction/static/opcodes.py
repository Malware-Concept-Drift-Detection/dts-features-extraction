import capstone
from collections import Counter

from src.feature_extraction.static.static_feature_extractor import StaticFeatureExtractor
from src.feature_extraction import config
import math
import pefile
import os


class OpCodesExtractor(StaticFeatureExtractor):

    def extract(self, sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.MALWARE_DIRECTORY, family, sha1)
        try:
            pe = pefile.PE(filepath)
            eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            code_section = pe.get_section_by_rva(eop)
            code_dump = code_section.get_data()
            code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            opcodes = [str(i.mnemonic) for i in md.disasm(code_dump, code_addr)]
            ngrams = Counter()
            for i in range(1, config.OPCODES_MAX_SIZE + 1):
                for j in range(len(opcodes) - i):
                    ngram = ' '.join(opcodes[j:j + i])
                    ngrams[ngram] += 1
            return {sha1: {'ngrams': ngrams, 'error': ''}}
        except Exception as e:
            return {sha1: {'ngrams': None, 'error': e}}

    def extract_and_pad(self, args):
        filepath, top_opcodes, N = args
        pe = pefile.PE(filepath)
        eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = pe.get_section_by_rva(eop)
        code_dump = code_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        opcodes = [str(i.mnemonic) for i in md.disasm(code_dump, code_addr)]
        ngrams = Counter()
        for i in range(1, config.OPCODES_MAX_SIZE + 1):
            for j in range(len(opcodes) - i):
                ngram = ' '.join(opcodes[j:j + i])
                ngrams[ngram] += 1
        tf_idfs = {"opcode_" + k: (self.tf(ngrams[k]) * self.idf(v, N) if k in list(ngrams.keys()) else 0.00)
                   for k, v in zip(top_opcodes.keys(), top_opcodes.values())}
        return tf_idfs

    @staticmethod
    def idf(x, N):
        return math.log(N / (1.0 + x))

    @staticmethod
    def tf(x):
        return math.log(1 + x)
