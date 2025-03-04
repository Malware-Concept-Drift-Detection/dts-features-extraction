# Static Features Extraction Engine

This project allows the user to extract static features from Windows PE files, which have been proven effective for malware family classification.

Specifically, the list of the chosen features and the extraction process itself adhere to the work proposed in the paper: [Decoding the Secrets of Machine Learning in Malware Classification: A Deep Dive into Datasets, Feature Extraction, and Model Performance](https://arxiv.org/pdf/2307.14657).

The project was carried out as part of my Master's thesis: *Clustering Windows Malware using Static Features and Concept Drift Detection*.

## Prerequisites

Make sure you have a running and active version of [Docker](https://docs.docker.com/engine/install/).

## Usage

- Configure the Docker Compose file by providing the following information:
  - `MALWARE_DIR_PATH`: the path where all the PE files are stored. The directory should group malwares based on their family, so it should contain $n$ subdirectories where $n$ is the number of families;
  - `VT_REPORTS_PATH`: the path of the VirusTotal reports. Each line of this file should be a separate json containing a report of a single PE file;
  - `MERGE_DATASET_PATH`: the path of the dataset that will be produced containing `[SHA256, family, submission-date]` of each file, starting from the VT reports file;
  - `FINAL_DATASET_DIR`: directory path where the final dataset with the extracted features will be stored.
- Deploy the engine to start the extraction process:
  ```bash
  docker compose up -d
  ```

## Authors

- Luca Fabri
