FROM python:3.13

WORKDIR /usr/app/

COPY . .

RUN pip install -r requirements.txt
RUN poetry install

CMD [ "poetry", "run", "python3", "-m", "src.feature_extraction.main", "--experiment", "data/"]