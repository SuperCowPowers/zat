# Installing ZAT on Raspberry Pi 4

### Raspberry Pi OS = Buster and Python = 3.7
These OS/Python version restrictions are based on dependency libraries like Pandas and scikit-learn. For these libraries you must have the 'Buster' version of the Raspberry Pi OS and you must use Python 3.7, this is because <https://www.piwheels.org> has built wheels for that OS/Python version and does not have wheels for other combinations (as of 01/01/2021). For example see: <https://www.piwheels.org/project/pandas/>

### Quick Guide

**Numpy Packages:** Many of the dependencies use **numpy** so we need to make sure the proper shared object libraries are installed on our Raspberry Pi.

```
$ sudo apt install libatlas-base-dev
```

### Now install ZAT
```
$ pip3 install zat
```
Now everything should be working (if not please see the [Trouble Shooting](#Trouble-Shooting) section below).

```
$ cd zat/examples
```
```
$ python3 zeek_to_pandas.py ../data/dhcp.log
                                              uid      id.orig_h  id.orig_p     id.resp_h  id.resp_p                mac    assigned_ip          lease_time    trans_id
ts
2013-09-15 23:44:10.691137024  Cm5veU18MVTniYSKAl  192.168.33.10         68  192.168.33.1         67  00:20:18:eb:ca:21  192.168.33.10 49710 days 06:23:20  2218089335
2013-09-15 23:44:23.734159104  Cm5veU18MVTniYSKAl  192.168.33.10         68  192.168.33.1         67  00:20:18:eb:ca:21  192.168.33.10 49710 days 06:23:20  2227948382
```

```
$ python3 zeek_to_scikit.py ../data/dns.log
Normalizing column Z...
Normalizing column query_length...
Rows in Cluster: 42
                                                       query  Z proto qtype_name          x         y  cluster
ts
2013-09-15 23:44:27.631939840                     guyspy.com  0   udp          A -70.971290 -0.036992        0
2013-09-15 23:44:27.696868864                 www.guyspy.com  0   udp          A -40.473601 -0.090177        0
2013-09-15 23:44:28.060638976   devrubn8mli40.cloudfront.net  0   udp          A -51.962069 -0.126854        0
2013-09-15 23:44:28.141794816  d31qbv1cthcecs.cloudfront.net  0   udp          A -49.478630 -0.072395        0
2013-09-15 23:44:28.422703872                crl.entrust.net  0   udp          A -66.493278 -0.042535        0
```

### Parquet Support 
If you'd like to include Parquet support this section is for you. Normally we'd use **pyarrow** for reading/writing **parquet**, but on Raspberry Pi it doesn't work (see **Details** section below), so we're going to setup **fastparquet** as the engine for reading/writing **parquet** files.

```
$ sudo apt install llvm-9
$ LLVM_CONFIG=/usr/lib/llvm-9/bin/llvm-config pip3 install fastparquet
```

### PySpark Support
Make sure **java** is installed, PySpark (included in ZAT) will automatically find it and you should be good to go.

```
$ sudo apt update
$ sudo apt install default-jdk
$ java -version
```

### Example that uses Parquet and PySpark

```
$ cd zat/examples
$ python3 zeek_to_parquet.py ../data/dns.log dns.parquet
...
<lots of Spark messages>
../data/dns.log --> dns.parquet
```



## Trouble Shooting
**Note: You only need to read this section if you're having issues**

### Seeing current version of installed OS/distro

```
$ cat /etc/os-release
PRETTY_NAME="Raspbian GNU/Linux 10 (buster)"

$ python3 --version
Python 3.7.3
```

### Upgrading your Raspberry Pi OS/Distro
```
sudo apt update
sudo apt full-upgrade
```


### Using virtualenv or pyenv
Either of these is totally fine as long as they are some version of Python 3.7 (3.7.9 or whatever). The only caveat here is that if you may need some libraries when you first create/pull new python versions.

**Pandas/LZMA** If you're using a virtualenv/pyenv you will probably to install the LZMA development libraries. Although this isn't strictly necessary, you'll get a big **UserWarning** message from Pandas every time you run something, so it's probably good to install it :)

Pyenv Python without the lzma package installed give this warning...

```
pandas/...: UserWarning: Could not import the lzma module.
```
To get rid of this warning and fix the issue..

```
$ pyenv uninstall 3.7.9
$ sudo apt install liblzma-dev
$ pyenv install 3.7.9
$ pyenv virtualenv 3.7.9 py37
```

### PyArrow Details
**Note:** There's an issue with **pyarrow** on Raspberry Pi, I have not had success in getting it installed. From the details on this ticket looks like it's an ARM support issue for the pyarrow library <https://github.com/piwheels/packages/issues/90>

### Contact Us
If you're still having issues or have questions just drop us an email at <support@supercowpowers.com>

