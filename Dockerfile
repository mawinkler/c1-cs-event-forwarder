# Start with the latest python 3.x version
FROM python:3.10.0-slim-bullseye

# Build App
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . .

RUN pip3 install --no-cache-dir -r requirements.txt && pip3 list

CMD ["python", "./cs_rslog.py"]