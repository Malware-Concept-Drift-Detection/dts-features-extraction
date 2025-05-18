import pefile

from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)


class HeadersExtractor(StaticFeatureExtractor):
    def extract(self, filepath):
        pe = pefile.PE(filepath)
        if pe.FILE_HEADER.Machine != 332:
            raise ValueError("File header machine != 332")

        headers = {}
        opt_header = pe.OPTIONAL_HEADER

        fields = [
            "SizeOfHeaders",
            "AddressOfEntryPoint",
            "ImageBase",
            "SizeOfImage",
            "SizeOfCode",
            "SizeOfInitializedData",
            "SizeOfUninitializedData",
            "BaseOfCode",
            "BaseOfData",
            "SectionAlignment",
            "FileAlignment",
        ]
        for f in fields:
            headers["header_{}".format(f)] = getattr(opt_header, f)

        coff_header = pe.FILE_HEADER
        fields = ["NumberOfSections", "SizeOfOptionalHeader"]
        for f in fields:
            headers["header_{}".format(f)] = getattr(coff_header, f)

        characteristics = coff_header.Characteristics
        characteristics = bin(characteristics)[2:]
        characteristics = "0" * (16 - len(characteristics)) + characteristics
        for i in range(16):
            headers["header_characteristics_bit{}".format(i)] = (
                characteristics[15 - i] == "1"
            )

        return headers
