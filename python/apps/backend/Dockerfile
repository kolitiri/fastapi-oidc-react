FROM python:3.8 as base
RUN pip install pipenv


FROM base as dev

WORKDIR /app
COPY ./Pipfile* /app
RUN pipenv install

COPY . /app

CMD pipenv run uvicorn backend.main:app --host 0.0.0.0 --reload


FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-slim as prd
# TODO
