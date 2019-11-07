"""Read Kafka Streams and Print out the messages"""
from __future__ import print_function
import sys
import argparse
from pprint import pprint
import json
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

# Local imports
from zat.utils import signal_utils


def exit_program():
    """Exit on Signal"""
    print('Exiting Program...')
    sys.exit()


if __name__ == '__main__':
    """Read Kafka Streams and Print out the messages"""

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, default='localhost:9092',
                        help='Specify the Kafka Server (default: localhost:9092)')
    parser.add_argument('--topics', type=lambda s: s.split(','), default='all',
                        help='Specify the Kafka Topics (e.g. dns   or   dns, http, blah   (defaults to all)')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Create a Kafka Consumer and subscribe to the topics
    all_topics = ['capture_loss', 'dns', 'http', 'ssl', 'weird', 'conn', 'files', 'x509']
    kserver = args.server
    topics = args.topics if args.topics != ['all'] else all_topics
    print('Subscribing to: {!r}'.format(topics))
    try:
        consumer = KafkaConsumer(*topics, bootstrap_servers=[kserver],
                                 value_deserializer=lambda x: json.loads(x.decode('utf-8')))
    except NoBrokersAvailable:
        print('Could not connect to Kafka server: {:s}'.format(args.server))
        sys.exit(-1)

    # Launch long lived process with signal catcher
    with signal_utils.signal_catcher(exit_program):

        # Now lets process our Kafka Messages
        for message in consumer:
            topic = message.topic
            message = message.value
            print('\n{:s}'.format(topic.upper()))
            pprint(message)
