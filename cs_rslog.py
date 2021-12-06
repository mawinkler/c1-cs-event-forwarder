#!/usr/bin/env python3
"""Example event forwarder for Container Security

Purpose of this forwarder it to send runtime security evets in CEF
format to SIEM or Big Data engines. Will be deprecated as soon as
Container Security is integrated with Vision One.
"""

import requests
import logging
import sys
import socket
import time
import yaml
from cefevent import CEFEvent
from datetime import datetime, timedelta

# Constants
_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
    'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

def syslog(message, level=LEVEL['notice'], facility=FACILITY['local3'],
    host='localhost', port=514):
    """
    Send syslog UDP packet to given host and port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = '<%d>%s' % (level + facility*8, message)
    sock.sendto(data.encode(), (host, port))
    sock.close()

def collect(c1_url,
            api_key,
            host,
            port,
            facility,
            interval):
    """
    Query for security events and send CEF via UDP to the receiver.
    
    Parameters
    ----------
    none

    Raises
    ------
    ValueError
        Houston, we have a problem

    Returns
    -------
    """

    _LOGGER.debug("Cloud One API endpoint: {}".format(c1_url))

    last_timestamp_sent = datetime.utcnow() - timedelta(minutes=(interval + 1))
    while True:
        # Setting start_time to utcnow - (INTERVAL + 1) to create a little overlap
        start_time = (datetime.utcnow() - timedelta(minutes=(interval + 1))).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # API query and response parsing here
        cursor = ""
        events = []
        while True:
            url = "https://container." + c1_url + "/api/events/sensors?" \
                + "next=" + cursor \
                + "&limit=" + str(25) \
                + "&fromTime=" + start_time \
                + "&toTime=" + end_time
            post_header = {
                "Content-Type": "application/json",
                "Authorization": "ApiKey " + api_key,
                "api-version": "v1",
            }
            try:
                response = requests.get(
                    url, headers=post_header, verify=True
                )

                response.encoding = response.apparent_encoding
                response.raise_for_status()
            except requests.exceptions.Timeout as err:
                _LOGGER.error(response.text)
                raise SystemExit(err)
            except requests.exceptions.HTTPError as err:
                _LOGGER.error(response.text)
                raise SystemExit(err)
            except requests.exceptions.RequestException as err:
                # catastrophic error. bail.
                _LOGGER.error(response.text)
                raise SystemExit(err)

            response = response.json()
            # Error handling
            if "message" in response:
                if response['message'] == "Invalid API Key":
                    _LOGGER.error("API error: {}".format(response['message']))
                    raise ValueError("Invalid API Key")

            events_count = len(response.get('events', {}))
            _LOGGER.debug("Number of events in result set: %d", events_count)
            if events_count > 0:
                for event in response.get('events', {}):
                    events.append(event)

            cursor = response.get('next', "")
            if cursor == "":
                break

        _LOGGER.debug("{} Container Security runtime events received".format(str(len(events))))

        # message format:
        # CEF:Version|Device Vendor|Device Product|Rule ID|Name|Severity|Extension
        # sample:
        # CEF:0|Trend Micro|Cloud One Container Security|1.0|0|TM-00000006|(T1059.004)Terminal shell in container|5|Extension
        # Extension: ruleID clusterID clusterName mitigation policyName k8s.ns.name k8s.pod.name proc.cmdline proc.pname container.id
        #            container.image.tag container.image.repository container.image.digest
        if len(events) > 0:
            # Since we might get an unorderd event list we need to check for the latest timestamp
            # in the events list
            event_timestamp_max = last_timestamp_sent
            for event in reversed(events):
                event_timestamp = datetime.strptime(event['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
                if (event_timestamp > last_timestamp_sent):
                    if (event_timestamp > event_timestamp_max):
                        event_timestamp_max = datetime.strptime(event['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

                    c = CEFEvent()
                    c.set_field('name', event['name'])
                    c.set_field('deviceVendor' , "Trend Micro")
                    c.set_field('deviceProduct', 'Cloud One Container Security')
                    c.set_field('rt', event['timestamp'])
                    c.set_field('severity', str(LEVEL[event['severity']]))
                    c.set_field('message',
                        "details" + " " +
                        "ruleID=" + event['ruleID'] + " " +
                        "clusterID=" + event['clusterID'] + " " +
                        "clusterName=" + event['clusterName'] + " " +
                        "mitigation=" + event['mitigation'] + " " +
                        "policyName=" + event['policyName'] + " " +
                        "k8s.ns.name=" + event['k8s.ns.name'] + " " +
                        "k8s.pod.name=" + event['k8s.pod.name'] + " " +
                        "proc.cmdline=" + event['proc.cmdline'] + " " +
                        "proc.pname=" + event.get('proc.pname', '<NA>') + " " +
                        "container.id=" + event['container.id'] + " " +
                        "container.image.tag=" + event['container.image.tag'] + " " +
                        "container.image.repository=" + event['container.image.repository'] + " " +
                        "container.image.digest=" + event['container.image.digest']
                    )
                    c.build_cef()
                    syslog(c, level=LEVEL[event['severity']], facility=FACILITY[facility], host=host, port=port)

                    # Return results
                    _LOGGER.debug("Event sent")
            last_timestamp_sent = event_timestamp_max
        time.sleep(interval * 60)

if __name__ == '__main__':

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    collect(cfg['cloudone']['c1_url'],
            cfg['cloudone']['api_key'],
            cfg['server']['host'],
            cfg['server']['port'],
            cfg['server']['facility'],
            cfg['interval'])
