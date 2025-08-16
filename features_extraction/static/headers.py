import pefile

from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)


class HeadersExtractor(StaticFeatureExtractor):
    def extract(self, filepath):
        pe = pefile.PE(filepath)
        headers = {}

        # Optional header fields
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
            "BaseOfData",  # only in PE32, check existence
            "SectionAlignment",
            "FileAlignment",
        ]
        for f in fields:
            headers["header_{}".format(f)] = getattr(opt_header, f, 0)

        # COFF header fields
        coff_header = pe.FILE_HEADER
        for f in ["NumberOfSections", "SizeOfOptionalHeader"]:
            headers["header_{}".format(f)] = getattr(coff_header, f)

        # Characteristics bits
        characteristics = coff_header.Characteristics
        characteristics_bin = bin(characteristics)[2:].zfill(16)
        for i in range(16):
            headers[f"header_characteristics_bit{i}"] = (
                characteristics_bin[15 - i] == "1"
            )

        return headers
