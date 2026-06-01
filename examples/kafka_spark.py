"""Read Kafka Streams into Spark, perform simple filtering/aggregation."""

import argparse
import sys
from time import sleep

try:
    import pyspark
    from pyspark.sql import SparkSession
    from pyspark.sql.functions import col, from_json, udf
    from pyspark.sql.types import BooleanType, IntegerType, StringType, StructType
except ImportError:
    print("\npip install pyspark")
    sys.exit(1)

try:
    import tldextract
except ImportError:
    print("\nThis example needs tldextract. Please do a $pip install tldextract and rerun this example")
    sys.exit(1)


def exit_program():
    """Exit on Signal"""
    print("Exiting Program...")
    sys.exit()


def compute_domain(query):
    # Pull out the domain
    if not query:
        return None
    if query.endswith(".local"):
        return "local"
    return tldextract.extract(query).registered_domain or query


def spark_kafka_package(spark_version):
    """Return the Spark Kafka connector coordinate that matches the PySpark version."""
    major_version = spark_version.split(".", maxsplit=1)[0]
    scala_binary_version = {"2": "2.11", "3": "2.12", "4": "2.13"}.get(major_version, "2.12")
    return "org.apache.spark:spark-sql-kafka-0-10_{:s}:{:s}".format(scala_binary_version, spark_version)


def dns_log_schema():
    """Return a Spark schema for Zeek DNS JSON messages emitted by the Kafka plugin."""
    return (
        StructType()
        .add("ts", StringType())
        .add("uid", StringType())
        .add("id.orig_h", StringType())
        .add("id.orig_p", IntegerType())
        .add("id.resp_h", StringType())
        .add("id.resp_p", IntegerType())
        .add("proto", StringType())
        .add("trans_id", IntegerType())
        .add("query", StringType())
        .add("qclass", IntegerType())
        .add("qclass_name", StringType())
        .add("qtype", IntegerType())
        .add("qtype_name", StringType())
        .add("rcode", IntegerType())
        .add("rcode_name", StringType())
        .add("AA", BooleanType())
        .add("TC", BooleanType())
        .add("RD", BooleanType())
        .add("RA", BooleanType())
        .add("Z", IntegerType())
        .add("answers", StringType())
        .add("TTLs", StringType())
        .add("rejected", BooleanType())
    )


def build_dns_counts(raw_data):
    """Parse, filter, enrich, and aggregate a Zeek DNS Kafka stream."""
    parsed_data = raw_data.select(from_json(col("value").cast("string"), dns_log_schema()).alias("data")).select(
        "data.*"
    )

    filtered_data = parsed_data.filter(col("query").isNotNull() & (col("query") != "") & ~col("query").like("%.local"))

    udf_compute_domain = udf(compute_domain, StringType())
    computed_data = filtered_data.withColumn("domain", udf_compute_domain("query"))
    return computed_data.groupBy("`id.orig_h`", "domain", "qtype_name").count()


if __name__ == "__main__":
    """Read Kafka Streams into Spark, perform simple filtering/aggregation"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server", type=str, default="localhost:9092", help="Specify the Kafka Server (default: localhost:9092)"
    )
    parser.add_argument("--topic", type=str, default="dns", help="Specify the Kafka topic to read (default: dns)")
    parser.add_argument(
        "--kafka-package",
        type=str,
        default=None,
        help="Override the Spark Kafka package coordinate if your Spark distribution uses a different Scala build",
    )
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print("Unrecognized args: %s" % commands)
        sys.exit(1)

    # Grab the Kafka server
    kserver = args.server

    kafka_package = args.kafka_package or spark_kafka_package(pyspark.__version__)

    # Spin up a local Spark Session (with 4 executors)
    spark = (
        SparkSession.builder.master("local[4]")
        .appName("zeek_streaming_etl")
        .config("spark.jars.packages", kafka_package)
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    # Optimize the conversion to Spark
    spark.conf.set("spark.sql.execution.arrow.enable", "true")

    # SUBSCRIBE: Setup connection to Kafka Stream
    raw_data = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", kserver)
        .option("subscribe", args.topic)
        .option("startingOffsets", "earliest")
        .load()
    )

    # ETL/FILTER/COMPUTE/AGGREGATE: Build the DNS count streaming pipeline
    group_data = build_dns_counts(raw_data)

    # At any point in the pipeline you can see what you're getting out
    group_data.printSchema()

    # Take the end of our pipeline and pull it into memory
    dns_count_memory_table = (
        group_data.writeStream.format("memory").queryName("dns_counts").outputMode("complete").start()
    )

    # Let the pipeline pull some data
    print("Pulling pipeline...Please wait...")

    # Create a Pandas Dataframe by querying the in memory table and converting
    # Loop around every 5 seconds to update output
    for _ in range(10):
        sleep(5)
        dns_counts_df = spark.sql("select * from dns_counts").toPandas()
        print("\nDNS Query Total Counts = {:d}".format(dns_counts_df["count"].sum()))
        print(dns_counts_df.sort_values(ascending=False, by="count"))

    # Stop the stream
    dns_count_memory_table.stop()
    sleep(1)
