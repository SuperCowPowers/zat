## Zeek with Kafka Plugin Notes
**Disclaimer:** These are simply my notes that I've captured after getting Bro/Kafka Plugin setup on my Mac. Your mileage may vary.

**Context:**
In general the process of getting the Kafka Plugin working on my Mac laptop was a bit tricky. One could certainly argue that setting up Zeek on your Mac Laptop is a bad idea to begin with, which might be true, but I like to use my laptop as a 'workbench' to experiment with stuff.

**Useful Links:**

- Zeek Network Monitor: <https://www.zeek.org>
- Kafka Zeek Plugin: <https://github.com/apache/metron-bro-plugin-kafka>
- Kafka: <https://kafka.apache.org>
- Spark: <https://spark.apache.org>

### Zeek Install

- When building Zeek I had issue with the configuration finding my 'venv python' (I used pyenv) and then python tools for Zeek were really unhappy later.
- I had to ```brew instal python@2``` to get Zeek to be happy with the python it found and properly build things like 'zeekctl' and the other Python utilities.
- With Python 'fixed', the instructions to build from source worked fine (<https://docs.zeek.org/en/stable/install/install.html>)

### Kafka Plugin Install

- Using ```zkg``` to install and download the Kafka package never worked for me (see <https://github.com/apache/metron-bro-plugin-kafka>). The tests would fail (without any information) and the plugin would never install.
- So I installed the Kafka Plugin from source (instructions here: <https://github.com/apache/metron-bro-plugin-kafka>)
- The from source installation went fine but I needed to change how the package was referenced when doing the ```@load``` command from my ```local.zeek``` file (see below).

### Slightly different @load command
I needed to put a different load command when 'activating' the Kafka plugin in my local.zeek configuration file. Here's what I added to the 'standard' site/local.zeek file.

```
@load Apache/Kafka
redef Kafka::topic_name = "";
redef Kafka::send_all_active_logs = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "localhost:9092"
);
```
- The first line took me a while to figure out
- The rest is, at least for me, the best setup:

  By putting in a blank topic name, all output topics are labeled with the name of their log file. For instance, stuff that goes to dns.log is mapped to the 'dns' Kafka topic, http.log to the 'http' topic, and so on. This was exactly what I wanted.

There's a much deeper explanation of all the options here (<https://github.com/apache/metron-bro-plugin-kafka>)

### Kafka Install
Thankfully installing Kafka on my Mac was super easy.

```
brew install kafka
```

## All Done
Well it doesn't seem that hard after writing it up but some of the details took me a while to figure out. Now we can test our new setup.

### Run Zeek

```
$ zeek -i en0 <path to>/local.zeek
```

### Run a simple Kafka consumer

```
$ kafka-console-consumer --bootstrap-server localhost:9092 --topic dns
```

## Related Stuff

- Kafka lightweight consumer/producer [KafkaCat](https://github.com/edenhill/kafkacat)
- [Kafka Python Tutorial](https://towardsdatascience.com/kafka-python-explained-in-10-lines-of-code-800e3e07dad1)