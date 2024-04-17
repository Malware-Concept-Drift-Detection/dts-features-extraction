FROM python:3.11

WORKDIR /usr/app

COPY . ./feature_extraction/

RUN pip install .

CMD [ "python3", "-m", "src.feature_extraction.main", "--experiment", "data/"]