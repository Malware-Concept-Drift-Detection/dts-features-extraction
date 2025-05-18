FROM python:3.11

WORKDIR /usr/app/

COPY . .

RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

RUN poetry install

CMD [ "poetry", "run", "python3", "-m", "features_extraction.main", "--experiment", "data/"]