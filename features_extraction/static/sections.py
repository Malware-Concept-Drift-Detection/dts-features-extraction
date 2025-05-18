from features_extraction.static.static_feature_extractor import (
    StaticFeatureExtractor,
)
from features_extraction.config.config import config
import array
import pefile
import math
import os


class SectionsExtractor(StaticFeatureExtractor):
    def extract(self, args):
        filepath, all_sections = args
        pe = pefile.PE(filepath)
        if pe.FILE_HEADER.Machine != 332:
            raise ValueError("File header machine != 332")

        secs = {}
        num = 1
        entrypoint_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entrypoint_valid = False
        for section in pe.sections:
            features = {}
            try:
                features["name"] = section.Name.decode().rstrip("\0")
            except:
                features["name"] = str(section.Name)

            characteristics = section.Characteristics
            characteristics = bin(characteristics)[2:]
            characteristics = "0" * (32 - len(characteristics)) + characteristics
            for i in range(32):
                features["characteristics_bit{}".format(i)] = (
                    characteristics[31 - i] == "1"
                )

            features["size"] = section.SizeOfRawData
            features["virtualSize"] = section.Misc_VirtualSize
            features["virtualAddress"] = section.VirtualAddress
            features["physicalAddress"] = section.Misc_PhysicalAddress
            features["entropy"] = section.get_entropy()
            features["rawAddress(pointerToRawData)"] = section.PointerToRawData
            features["pointerToRelocations"] = section.PointerToRelocations
            features["numberOfRelocations"] = section.NumberOfRelocations

            for fname, fvalue in features.items():
                secs["pesection_{}_{}".format(num, fname)] = fvalue

            if (
                entrypoint_addr >= features["virtualAddress"]
                and (entrypoint_addr - features["virtualAddress"])
                < features["virtualSize"]
            ):  # this is the sections which entry point is in it!!!
                for fname, fvalue in features.items():
                    secs["pesectionProcessed_entrypointSection_{}".format(fname)] = (
                        fvalue
                    )
                entrypoint_valid = True

            num += 1

        if not entrypoint_valid:
            return

        entropies = [
            value for feature, value in secs.items() if feature.endswith("_entropy")
        ]
        if len(entropies):
            mean_entropy = sum(entropies) / float(len(entropies))
            min_entropy = min(entropies)
            max_entropy = max(entropies)
        else:
            mean_entropy = 0
            min_entropy = 0
            max_entropy = 0

        sizes = [value for feature, value in secs.items() if feature.endswith("_size")]
        if len(sizes):
            mean_size = sum(sizes) / float(len(sizes))
            min_size = min(sizes)
            max_size = max(sizes)
        else:
            mean_size = 0
            min_size = 0
            max_size = 0

        virtual_sizes = [
            value for feature, value in secs.items() if feature.endswith("_virtualSize")
        ]
        if len(virtual_sizes):
            mean_virtual_size = sum(virtual_sizes) / float(len(virtual_sizes))
            min_virtual_size = min(virtual_sizes)
            max_virtual_size = max(virtual_sizes)
        else:
            mean_virtual_size = 0
            min_virtual_size = 0
            max_virtual_size = 0

        secs["pesectionProcessed_sectionsMeanEntropy"] = mean_entropy
        secs["pesectionProcessed_sectionsMinEntropy"] = min_entropy
        secs["pesectionProcessed_sectionsMaxEntropy"] = max_entropy

        secs["pesectionProcessed_sectionsMeanSize"] = mean_size
        secs["pesectionProcessed_sectionsMinSize"] = min_size
        secs["pesectionProcessed_sectionsMaxSize"] = max_size

        secs["pesectionProcessed_sectionsMeanVirtualSize"] = mean_virtual_size
        secs["pesectionProcessed_sectionsMinVirtualSize"] = min_virtual_size
        secs["pesectionProcessed_sectionsMaxVirtualSize"] = max_virtual_size

        secs.update(self.__parse_resources(pe))

        return self.__pad_sections(secs, all_sections)

    @staticmethod
    def __get_max_sections(sha1_family):
        sha1, family = sha1_family
        filepath = os.path.join(config.malware_directory_path, family, sha1)
        pe = pefile.PE(filepath)
        if pe.FILE_HEADER.Machine != 332:
            return -1
        else:
            return len(pe.sections)

    @staticmethod
    def __get_entropy(data):
        if len(data) == 0:
            return 0.0
        occurences = array.array("L", [0] * 256)
        for x in data:
            occurences[x if isinstance(x, int) else ord(x)] += 1

        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)

        return entropy

    def __parse_resources(self, pe):
        entropies = []
        sizes = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, "directory"):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size,
                                )
                                size = resource_lang.data.struct.Size
                                entropy = self.__get_entropy(data)

                                entropies.append(entropy)
                                sizes.append(size)

        assert len(entropies) == len(sizes)
        if len(sizes):
            mean_entropy = sum(entropies) / float(len(entropies))
            min_entropy = min(entropies)
            max_entropy = max(entropies)
            mean_size = sum(sizes) / float(len(sizes))
            min_size = min(sizes)
            max_size = max(sizes)
            resources_nb = len(entropies)
        else:
            mean_entropy = 0
            min_entropy = 0
            max_entropy = 0
            mean_size = 0
            min_size = 0
            max_size = 0
            resources_nb = 0

        secs = {}

        secs["pesectionProcessed_resourcesMeanEntropy"] = mean_entropy
        secs["pesectionProcessed_resourcesMinEntropy"] = min_entropy
        secs["pesectionProcessed_resourcesMaxEntropy"] = max_entropy

        secs["pesectionProcessed_resourcesMeanSize"] = mean_size
        secs["pesectionProcessed_resourcesMinSize"] = min_size
        secs["pesectionProcessed_resourcesMaxSize"] = max_size

        secs["pesectionProcessed_resources_nb"] = resources_nb

        return secs

    @staticmethod
    def __pad_sections(sections, all_sections):
        padded_sections = dict.fromkeys(all_sections)
        for section_feature in all_sections:
            if section_feature in sections.keys():
                padded_sections[section_feature] = sections[section_feature]
            else:
                if all_sections[section_feature] == "object":
                    padded_sections[section_feature] = "none"
                elif all_sections[section_feature] == "int64":
                    padded_sections[section_feature] = int(0)
                elif all_sections[section_feature] == "float64":
                    padded_sections[section_feature] = float(0.00)
                else:
                    padded_sections[section_feature] = False
        return padded_sections
