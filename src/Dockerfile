FROM python:3.8-slim

WORKDIR /api-flask

COPY ./requirements.txt /api-flask
COPY ./repository/ /api-flask/repository
COPY ./utils/ /api-flask/utils

RUN pip3 install --upgrade pip && pip install --no-cache-dir -r requirements.txt


EXPOSE 5005

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5005", "-w", "4", "--reload", "--reload-extra-file", "repository/", "--reload-extra-file", "utils/"]
