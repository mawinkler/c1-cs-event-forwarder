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
import json
import pprint
from operator import itemgetter
from cefevent import CEFEvent
from datetime import datetime, timedelta

# Constants
_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO,
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


def collect_rt(c1_url,
               api_key,
               start_time,
               end_time):
    """
    Collect runtime events from Container Security within a given time range
    
    Parameters
    ----------
    c1_url
    api_key
    start_time
    end_time

    Raises
    ------
    Timeout
        The request timed out.
    HTTPError
        An HTTP error occurred.
    RequestException
        There was an ambiguous exception that occurred while handling our request.
    ValueError
        Houston, we have a problem
    """

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
            break
        except requests.exceptions.HTTPError as err:
            _LOGGER.error(response.text)
            break
        except requests.exceptions.RequestException as err:
            # catastrophic error. bail.
            _LOGGER.error(response.text)
            break

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

    _LOGGER.info("{} runtime events received".format(str(len(events))))

    return events


def collect_dc(c1_url,
               api_key,
               start_time,
               end_time):
    """
    Collect deployment and continuous events from Container Security within a given time range
    
    Parameters
    ----------
    c1_url
    api_key
    start_time
    end_time

    Raises
    ------
    Timeout
        The request timed out.
    HTTPError
        An HTTP error occurred.
    RequestException
        There was an ambiguous exception that occurred while handling our request.
    ValueError
        Houston, we have a problem
    """

    # API query and response parsing here
    cursor = ""
    events = []
    while True:
        url = "https://container." + c1_url + "/api/events/evaluations?" \
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
            break
        except requests.exceptions.HTTPError as err:
            _LOGGER.error(response.text)
            break
        except requests.exceptions.RequestException as err:
            # catastrophic error. bail.
            _LOGGER.error(response.text)
            break

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

    _LOGGER.info("{} deployment and continuous events received".format(str(len(events))))

    return events


def cef_rt(event, facility, host, port):
    """
    Creates a CEF event from a runtime event
    
    Parameters
    ----------
    event
    facility
    host
    port
    """

    # message format:
    # CEF:Version|Device Vendor|Device Product|Rule ID|Name|Severity|Extension
    # sample:
    # CEF:0|Trend Micro|Cloud One Container Security|1.0|0|TM-00000006|(T1059.004)Terminal shell in container|5|Extension
    # Extension: ruleID clusterID clusterName mitigation policyName k8s.ns.name k8s.pod.name proc.cmdline proc.pname container.id
    #            container.image.tag container.image.repository container.image.digest

    # pprint.pprint(event)

    c = CEFEvent()

    c.set_field('name', event['name'])
    c.set_field('deviceVendor' , 'Trend Micro')
    c.set_field('deviceProduct', 'Cloud One Container Security Runtime')
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
        "container.image.digest=" + event['container.image.digest'])

    syslog(c, level=LEVEL[event['severity']], facility=FACILITY[facility], host=host, port=port)
    _LOGGER.debug("Runtime event sent")


def cef_dc(event, facility, host, port):
    """
    Creates CEF event(s) from deployment or continious events
    
    Parameters
    ----------
    event
    facility
    host
    port
    """

    # message format:
    # CEF:Version|Device Vendor|Device Product|Rule ID|Name|Severity|Extension
    # sample:
    # CEF:0|Trend Micro|Cloud One Container Security|1.0|0|TM-00000006|(T1059.004)Terminal shell in container|5|Extension
    # Extension: action mitigation clusterID clusterName decision exceptions kind namespace operation
    #            policyDefinitionName policyName reason.action reason.resources reason.rule reason.type

    # pprint.pprint(event)

    # If we don't have a reason, it's an allow and we populate the event with an empty reason
    if len(event['reasons']) == 0:
        reason = {'action': '<N/A>',
                  'resources': [],
                  'rule': '<N/A>',
                  'type': 'Allow'}
        cef_dc_reasons(event, reason, facility, host, port)
    else:
        for reason in event['reasons']:
            cef_dc_reasons(event, reason, facility, host, port)


def cef_dc_reasons(event, reason, facility, host, port):
    """
    Creates a CEF event from a deployment or continuous event and reason
    
    Parameters
    ----------
    event
    reason
    facility
    host
    port
    """

    # We don't have a severity in deploy or continuous events, so we set allow to `info`
    # and everything else to `warning`
    severity = ""
    if (event['decision'] == 'allow'):
        severity = LEVEL['info']
    else:
        severity = LEVEL['warning']

    # Building one event per reason
    c = CEFEvent()
    c.set_field('name', reason['type'].capitalize())
    c.set_field('deviceVendor' , 'Trend Micro')
    c.set_field('deviceProduct', 'Cloud One Container Security Deploy')
    c.set_field('rt', event['timestamp'])
    c.set_field('severity', str(severity))
    c.set_field('message',
        "details" + " " +
        "action=" + event.get('action', '<N/A>') + " " +
        "mitigation=" + event.get('mitigation', '<N/A>') + " " +
        "clusterID=" + event['clusterID'] + " " +
        "clusterName=" + event['clusterName'] + " " +
        "decision=" + event['decision'] + " " +
        "exceptions=" + json.dumps(event.get('exceptions', [])) + " " +
        "kind=" + event['kind'] + " " +
        "namespace=" + event['namespace'] + " " +
        "operation=" + event.get('operation', '<N/A>') + " " +
        "policyDefinitionName=" + event['policyDefinitionName'] + " " +
        "policyName=" + event.get('policyName', '<NA>') + " " +
        "reason.action=" + reason['action'] + " " +
        "reason.resources=" + json.dumps(reason['resources']) + " " +
        "reason.rule=" + reason.get('rule', '<N/A>') + " " +
        "reason.type=" + reason['type']
    )
    c.build_cef()
    syslog(c, level=severity, facility=FACILITY[facility], host=host, port=port)
    _LOGGER.debug("Deployment or continuous event sent")


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
    c1_url
    api_key
    host
    port
    facility
    interval
    """

    _LOGGER.debug("Cloud One API endpoint: {}".format(c1_url))

    last_timestamp_sent = datetime.utcnow() - timedelta(minutes=(interval + 1))
    while True:
        # Setting start_time to utcnow - (INTERVAL + 2) to create a little overlap
        start_time = (datetime.utcnow() - timedelta(minutes=(interval + 2))).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        events = []
        _LOGGER.info("Query deployment and continuous events")
        events += collect_dc(c1_url,
                             api_key,
                             start_time,
                             end_time)

        _LOGGER.info("Query runtime events")
        events += collect_rt(c1_url,
                             api_key,
                             start_time,
                             end_time)

        if len(events) > 0:

            event_timestamp_max = last_timestamp_sent
            for event in sorted(events, key=itemgetter('timestamp')):
                event_timestamp = datetime.strptime(event['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
                if (event_timestamp > last_timestamp_sent):
                    if (event_timestamp > event_timestamp_max):
                        event_timestamp_max = datetime.strptime(event['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

                    if (event.get('type', None) == "falco"):
                        cef_rt(event, facility, host, port)
                    else:
                        cef_dc(event, facility, host, port)

            last_timestamp_sent = event_timestamp_max

        time.sleep(interval * 60)
    

if __name__ == '__main__':

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    _LOGGER.info("Event forwarder started.")
    collect(cfg['cloudone']['c1_url'],
            cfg['cloudone']['api_key'],
            cfg['server']['host'],
            cfg['server']['port'],
            cfg['server']['facility'],
            cfg['interval'])
