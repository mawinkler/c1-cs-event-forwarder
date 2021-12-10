# Cloud One Container Security Runtime Events Forwarder

Queries events interval based the Runtime Security sensors and evaluation events from Deployment and Continuous Compliance of Cloud One Container Security. The events are forwarded in CEF format to SIEM / Big Data Engines. Tested with Splunk Enterprise only.

![alt text](images/splunk.png "Splunk Search")

For the CEF event formatting I'm using <https://github.com/kamushadenes/cefevent>

> Currently, only CEF via UDP is supported.

## Usage

Create a config.yml based on the sample file provided and run 

```sh
./cs_events.py
```

To run in continuously, simply run it as a container:

```sh
docker build -t c1cs-events .
docker run --rm -d --name c1cs-events c1cs-events
```

## Quickly start a Splunk

`docker-compose.yaml`:

```yaml
version: "3.6"

services:
  splunk:
    image: ${SPLUNK_IMAGE:-splunk/splunk:latest}
    container_name: so1
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD
      - SPLUNK_ADD=tcp 1514
      - TZ=Europe/Berlin
      - PHP_TZ=Europe/Berlin
    volumes:
      - opt-splunk-etc:/opt/splunk/etc
      - opt-splunk-var:/opt/splunk/var
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    ports:
      - 1514:1514
      - 8880:8000
      - 50514:50514/udp

volumes:
  opt-splunk-etc:
  opt-splunk-var:
```

## Support

This is an Open Source community project. Project contributors may be able to help, depending on their time and availability. Please be specific about what you're trying to do, your system, and steps to reproduce the problem.

For bug reports or feature requests, please [open an issue](../../issues). You are welcome to [contribute](#contribute).

Official support from Trend Micro is not available. Individual contributors may be Trend Micro employees, but are not official support.

## Contribute

I do accept contributions from the community. To submit changes:

1. Fork this repository.
1. Create a new feature branch.
1. Make your changes.
1. Submit a pull request with an explanation of your changes or additions.

I will review and work with you to release the code.
