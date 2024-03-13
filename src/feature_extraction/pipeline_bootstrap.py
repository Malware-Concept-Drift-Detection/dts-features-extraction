import config
import os
import extract_features as ef
from collections import Counter
from p_tqdm import p_map
from functools import partial
import src.feature_extraction.static.sections as sections


def check_broken():
    # Check those samples that fail the extraction of sections and opcodes
    check = []

    # Goodware
    goodware = os.listdir(config.GOODWARE_DIRECTORY)
    check.extend(zip(goodware, [None] * len(goodware)))

    # Malware
    families = os.listdir(config.MALWARE_DIRECTORY)
    for family in families:
        current_samples = os.listdir(os.path.join(config.MALWARE_DIRECTORY, family))
        check.extend(zip(current_samples, [family] * len(current_samples)))

    # Check the maximum number of sections
    results = p_map(sections.get_max_sections, check, num_cpus=config.CORES)
    max_sections = max(results)

    # Generate all_sections File
    with open(os.path.join('PRE_topFeatures', 'sectionProcessedTemplate'), 'r') as rFile:
        section_template_processed = rFile.read().splitlines()
    with open(os.path.join('PRE_topFeatures', 'section_template'), 'r') as rFile:
        section_template = rFile.read().splitlines()

    to_write = section_template_processed.copy()
    for section in range(1, max_sections + 1):
        to_write.extend([f'pesection_{section}_{x}' for x in section_template])

    with open(os.path.join('PRE_topFeatures', 'all_sections.list'), 'w') as w_file:
        w_file.write("\n".join(to_write))

    # TOP Sections needed
    with open(os.path.join('PRE_topFeatures', 'all_sections.list'), 'r') as sectionFile:
        all_sections = {k: v for k, v in (l.split('\t') for l in sectionFile.read().splitlines())}

    # Fake TOP Opcodes needed
    top_opcodes = {'add': 1}
    top_opcodes = Counter(top_opcodes)

    current_extracting_function = partial(ef.extract_features,
                                        N=10000,
                                        genericsFlag=False,
                                        headersFlag=False,
                                        allSections=all_sections,
                                        topStrings=None,
                                        topDlls=None,
                                        topImports=None,
                                        topN_grams=None,
                                        topOpcodes=top_opcodes
                                        )

    print('Looking for broken files...')
    # check = ('f5c009839a21f89a74b7d86e7957856401589d1c02d0f26e4a0d9e4409ee11de','cossta')
    # current_extracting_function(check)
    results = p_map(current_extracting_function, check, num_cpus=config.CORES)
    problematic_sha1s = [y for x, y in results if not x]
    problematic_sha1s = {k: v for d in problematic_sha1s for k, v in d.items()}
    with open(os.path.join(config.DATASET_DIRECTORY, 'staticFails'), 'w') as w_file:
        for sample, dictionary in problematic_sha1s.items():
            w_file.write(f'{sample}\t{dictionary["error"]}\n')

    print(f'{len(problematic_sha1s)} broken files found...')


if __name__ == '__main__':
    check_broken()
