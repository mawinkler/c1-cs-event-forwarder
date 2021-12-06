# Cloud One Container Security Runtime Events Forwarder

Queries events interval based from the Runtime Security sensors of Cloud One Container Security and forwards them in CEF format to SIEM / Big Data Engines. Tested with Splunk Enterprise only.

![alt text](images/splunk.png "Splunk Search")

For the CEF event formatting I'm using <https://github.com/kamushadenes/cefevent>

> Currently, only CEF via UDP is supported.

## Usage

Create a config.yml based on the sample file provided and run 

```sh
python3 cs_rslog.py
```

To run in continuously, simply run it as a container:

```sh
docker build -t c1cs-rslog .
docker run -d c1cs-rslog
```
