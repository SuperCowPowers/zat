"""KafkaRouter: The class takes in N Kafka input topics and produces M Kafka output topics"""

import sys
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import NoBrokersAvailable
from collections import defaultdict
import json
from pprint import pprint
from datetime import datetime

# Local imports
from zat.utils import signal_utils

class KafkaRouter(object):
    """KafkaRouter: The class takes in N Kafka input topics and produces M Kafka output topics

        Args:
            input_topics (list of strings): List of the initial input topics
            input_servers (list of strings): Kafka Bootstrap servers (default=['localhost:9092'])
            output_servers (list of strings): Kafka Bootstrap servers (default=['localhost:9092'])
    """
    def __init__(self, offset='latest', input_servers=['localhost:9092'], output_servers=['localhost:9092']):
        """Initialize the KafkaRouter class"""

        # Setup the input and output
        print('Initializing KafkaRouter: {!r}'.format(input_servers))
        try:
            self.input_pipe = KafkaConsumer(bootstrap_servers=input_servers, auto_offset_reset=offset,
                                           value_deserializer=lambda x: json.loads(x.decode('utf8')))
        except NoBrokersAvailable:
            print('Could not connect to Kafka bootstrap servers: {:s}'.format(input_servers))
            sys.exit(-1)
        try:
            self.output_pipe = KafkaProducer(bootstrap_servers=output_servers,
                                             value_serializer=lambda x: json.dumps(x).encode('utf8'))            
        except NoBrokersAvailable:
            print('Could not connect to Kafka bootstrap servers: {:s}'.format(output_servers))
            sys.exit(-1)

        # Gates
        self.route_info = {}
        self.routes = defaultdict(list)

        # Topics we're listening to
        self.topics = set()

    def add_route(self, topic, callback):
        """Add a logic route that pulls in a message from the input_pipe and sends messages 
           to the output_pipe with the specified topic"""
        self.route_info[callback.__name__] = callback
        self.routes[topic].append(callback)

        # Add this topic to our input pipe
        if topic not in self.topics:
            self.topics.add(topic)
            self.input_pipe.subscribe(list(self.topics))       
            print('Adding Topic {:s}'.format(topic))
            print('Topics: {!r}'.format(self.input_pipe.subscription()))


    def run(self):
        """Run the KafkaRouter with all of the registered logic routes"""
        with signal_utils.signal_catcher(self.exit_program):
    
            # Now lets process our Kafka Messages
            for message in self.input_pipe:
                topic = message.topic
                message = message.value
                for route in self.routes[topic]:
                    topic = route(message)
                    if topic:
                        self.output_pipe.send(topic, message)
                        # self.output_pipe.poll()  # What do we want to do here?

    def list_routes(self):
        print('{!r}'.format(self.route_info))

    def exit_program(self):
        """Exit on Signal"""
        print('Exiting Program...')
        sys.exit()       

# Simple test of the functionality
def disabled_test():
    """Test for KafkaRouter Class"""
    from zat.utils import geo_lookup
    my_geo = geo_lookup.GeoLookup()

    # Make some simple logic routes
    def north_south(message):
        if (not message['local_orig']) and message['local_resp']:
            return 'incoming'
        elif message['local_orig'] and not message['local_resp']:
            return 'outgoing'
        return None

    def incoming_info(message):
        geo_info = my_geo.query_ip(message['id.orig_h'])
        timestamp = datetime.fromtimestamp(message['ts'])
        print('\nINCOMING')
        print(timestamp, geo_info['country_code'], geo_info['region_name'], message['id.orig_h'], '-->', message['id.resp_h'], 
              message['proto'], message.get('service', 'unknown'))
        return None

    def outgoing_info(message):
        ip = message['id.resp_h']
        # Skip broad-cast, multi-cast
        if ip[:3] in ['255', '239', '224']:
            return None

        # Get Geographical Information and Check for outside US traffic
        geo_info = my_geo.query_ip(message['id.resp_h'])
        if not geo_info or geo_info['country_code'] == 'US':
            return None

        # Add geo info and route to 'non_us'
        message['country_code'] = geo_info['country_code']
        message['region_name'] = geo_info['region_name']
        return 'non_us'

    def print_info(message):
        timestamp = datetime.fromtimestamp(message['ts'])
        print(timestamp, message['country_code'], message['region_name'], message['id.orig_h'], '-->', message['id.resp_h'], 
              message['proto'], message.get('service', 'unknown'))
        return None
        
            
    # Create the class and test it
    router = KafkaRouter(offset='earliest')
    router.add_route('conn', north_south)
    router.add_route('outgoing', outgoing_info)
    router.add_route('incoming', incoming_info)
    router.add_route('non_us', print_info)
    router.run()


if __name__ == "__main__":
    disabled_test()
