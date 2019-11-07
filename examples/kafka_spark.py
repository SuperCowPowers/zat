"""Read Kafka Streams into Spark, perform simple filtering/aggregation"""

import sys
import pyspark
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StringType, BooleanType, IntegerType
from pyspark.sql.functions import from_json, to_json, col, struct, udf

import argparse
from time import sleep

# Local imports
from zat.utils import signal_utils

# Third Party Imports
try:
    import tldextract
except ImportError:
    print('\nThis example needs tldextract. Please do a $pip install tldextract and rerun this example')
    sys.exit(1)


def exit_program():
    """Exit on Signal"""
    print('Exiting Program...')
    sys.exit()


def compute_domain(query):
    # Pull out the domain
    if query.endswith('.local'):
        return 'local'
    return tldextract.extract(query).registered_domain if query else None


if __name__ == '__main__':
    """Read Kafka Streams into Spark, perform simple filtering/aggregation"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=str, default='localhost:9092',
                        help='Specify the Kafka Server (default: localhost:9092)')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Grab the Kafka server
    kserver = args.server

    # Spin up a local Spark Session (with 4 executors)
    spark = SparkSession.builder.master('local[4]').appName('my_awesome') \
            .config('spark.jars.packages', 'org.apache.spark:spark-sql-kafka-0-10_2.11:2.4.4') \
            .getOrCreate()
    spark.sparkContext.setLogLevel('ERROR')

    # Optimize the conversion to Spark
    spark.conf.set("spark.sql.execution.arrow.enable", "true")

    # SUBSCRIBE: Setup connection to Kafka Stream 
    raw_data = spark.readStream.format('kafka').option('kafka.bootstrap.servers', kserver) \
                                               .option('subscribe', 'dns') \
                                               .option('startingOffsets', 'earliest').load()

    # Define the schema for the DNS message (do this better)
    dns_schema = StructType().add('ts', StringType()).add('uid', StringType()).add('id.orig_h', StringType()) \
                             .add('id.orig_p', IntegerType()).add('id.resp_h', StringType()).add('id.resp_p', IntegerType()) \
                             .add('proto', StringType()).add('trans_id', IntegerType()).add('query', StringType()) \
                             .add('qclass', IntegerType()).add('qclass_name', StringType()).add('qtype', IntegerType()) \
                             .add('qtype_name', StringType()).add('rcode', IntegerType()).add('rcode_name', StringType()) \
                             .add('AA', BooleanType()).add('TC', BooleanType()).add('RD', BooleanType()).add('RA', BooleanType()) \
                             .add('Z', IntegerType()).add('answers', StringType()).add('TTLs', StringType()).add('rejected', BooleanType())

    # ETL: Convert raw data into parsed and proper typed data
    parsed_data = raw_data.select(from_json(col('value').cast('string'), dns_schema).alias('data')).select('data.*')

    # FILTER: Only get DNS records that have 'query' field filled out
    filtered_data = parsed_data.filter(parsed_data.query.isNotNull() & (parsed_data.query!='')==True)

    # FILTER 2: Remove Local/mDNS queries
    filtered_data = filtered_data.filter(~filtered_data.query.like('%.local'))  # Note: using the '~' negation operator

    # COMPUTE: A new column with the 2nd level domain extracted from the query
    udf_compute_domain = udf(compute_domain, StringType())
    computed_data = filtered_data.withColumn('domain', udf_compute_domain('query'))

    # AGGREGATE: In this case a simple groupby operation
    group_data = computed_data.groupBy('`id.orig_h`', 'domain', 'qtype_name').count()

    # At any point in the pipeline you can see what you're getting out
    group_data.printSchema()

    # Take the end of our pipeline and pull it into memory
    dns_count_memory_table = group_data.writeStream.format('memory').queryName('dns_counts').outputMode('complete').start()

    # Let the pipeline pull some data
    print('Pulling pipline...Please wait...')

    # Create a Pandas Dataframe by querying the in memory table and converting
    # Loop around every 5 seconds to update output
    for _ in range(10):
        sleep(5)
        dns_counts_df = spark.sql("select * from dns_counts").toPandas()
        print('\nDNS Query Total Counts = {:d}'.format(dns_counts_df['count'].sum()))
        print(dns_counts_df.sort_values(ascending=False, by='count'))

    # Stop the stream
    dns_count_memory_table.stop()
    sleep(1)