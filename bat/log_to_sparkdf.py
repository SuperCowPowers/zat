"""LogToSparkDF: Converts a Bro log to a Spark DataFrame"""
from __future__ import print_function

# Third Party
from pyspark.sql.types import StructType, StringType, IntegerType, FloatType, LongType
from pyspark.sql.functions import col, when

# Local
from bat import bro_log_reader


class LogToSparkDF(object):
    """LogToSparkDF: Converts a Bro log to a Spark DataFrame"""

    def __init__(self, spark):
        """Initialize the LogToSparkDF class"""

        # Grab the spark context
        self.spark = spark

        # First Level Type Mapping
        #    This map defines the types used when first reading in the Bro log into a 'chunk' dataframes.
        #    Types (like time and interval) will be defined as one type at first but then
        #    will undergo further processing to produce correct types with correct values.
        # See: https://spark.apache.org/docs/latest/sql-reference.html
        #      for more info on supported types.
        self.type_map = {'bool': StringType(),   # Secondary Processing into BooleanType()
                         'count': LongType(),
                         'int': IntegerType(),
                         'double': FloatType(),
                         'time': FloatType(),    # Secondary Processing into TimestampType()
                         'interval': FloatType(),
                         'port': IntegerType(),
                         'enum': StringType(),
                         'addr': StringType(),
                         'string': StringType()
                         }

    def create_dataframe(self, log_filename):
        """ Create a Spark dataframe from a Bro/Zeek log file
            Args:
               log_fllename (string): The full path to the Bro log
        """

        # Create a Bro log reader just to read in the header for names and types
        _bro_reader = bro_log_reader.BroLogReader(log_filename)
        _, field_names, field_types, _ = _bro_reader._parse_bro_header(log_filename)

        # Get the appropriate types for the Spark Dataframe
        spark_schema = self.build_spark_schema(field_names, field_types)

        # Now actually read the Bro Log using Spark read CSV
        _df = self.spark.read.csv(log_filename, schema=spark_schema, sep='\t', comment="#", nullValue='-')

        # Secondary processing
        for name, f_type in zip(field_names, field_types):
            # Some field names may have '.' in them, so we have to backtick those fields
            ref_name = '`' + name + '`'
            if f_type == 'time':
                _df = _df.withColumn(name, _df[ref_name].cast('timestamp'))
            if f_type == 'bool':
                _df = _df.withColumn(name, when(col(ref_name) == 'T', 'true').when(col(ref_name) == 'F', 'false')
                                     .otherwise('null').cast('boolean'))

        # Return the spark dataframe
        return _df

    def build_spark_schema(self, column_names, column_types, verbose=False):
        """Given a set of names and types, construct a dictionary to be used
           as the Spark read_csv dtypes argument"""

        # If we don't know the type put it into a string
        unknown_type = StringType()

        schema = StructType()
        for name, bro_type in zip(column_names, column_types):

            # Grab the type
            spark_type = self.type_map.get(bro_type)

            # Sanity Check
            if not spark_type:
                if verbose:
                    print('Could not find type for {:s} using StringType...'.format(bro_type))
                spark_type = unknown_type

            # Add the Spark type for this column
            schema.add(name, spark_type)

        # Return the Spark schema
        return schema


# Simple test of the functionality
def test():
    """Test for LogToSparkDF Class"""
    import os
    from bat.utils import file_utils
    from pyspark.sql import SparkSession

    # Spin up a local Spark Session (with 4 executors)
    spark = SparkSession.builder.master('local[4]').appName('my_awesome').getOrCreate()

    # Grab a test file
    data_path = file_utils.relative_dir(__file__, '../data')
    log_path = os.path.join(data_path, 'ftp.log')

    # Convert it to a Spark DataFrame
    log_to_spark = LogToSparkDF(spark)
    spark_df = log_to_spark.create_dataframe(log_path)

    # Print out the head
    print(spark_df.show())

    # Print out the datatypes
    print(spark_df.printSchema())

    num_rows = spark_df.count()
    print("Number of Spark DataFrame rows: {:d}".format(num_rows))
    columns = spark_df.columns
    print("Columns: {:s}".format(','.join(columns)))

    # Test a bunch
    tests = ['app_stats.log', 'dns.log', 'http.log', 'notice.log', 'tor_ssl.log',
             'conn.log', 'dhcp.log', 'dhcp_002.log', 'files.log',  'smtp.log', 'weird.log',
             'ftp.log',  'ssl.log', 'x509.log']
    for log_path in [os.path.join(data_path, log) for log in tests]:
        print('Testing: {:s}...'.format(log_path))
        spark_df = log_to_spark.create_dataframe(log_path)
        print(spark_df.show())
        print(spark_df.printSchema())

    # Test an empty log (a log with header/close but no data rows)
    log_path = os.path.join(data_path, 'http_empty.log')
    spark_df = log_to_spark.create_dataframe(log_path)
    print(spark_df.show())
    print(spark_df.printSchema())

    print('LogToSparkDF Test successful!')


if __name__ == '__main__':
    # Run the test for easy testing/debugging
    test()
