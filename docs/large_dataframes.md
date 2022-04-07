## Performance on large dataframes

**TLDR:**
We've recently completed some enhancements to our Zeek log to Pandas dataframe class. The new class provides a smaller memory footprint and less time to read in a large log file. Also you can now specify exactly which columns you want with the 'usecols' option, like so:

```
df = log_to_df.create_dataframe(conn, usecols=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto'])
```

## Details on recent testing and changes
We have several outstanding issues for needed improvements to support the ingestion and processing of large Bro/Zeek log files.

- <https://github.com/SuperCowPowers/zat/issues/23>
- <https://github.com/SuperCowPowers/zat/issues/71>

There's also a PR from <https://github.com/bhklimk> with some good suggestions.

Big thanks to Benjamin Klimkowski <https://github.com/bhklimk>. The ideas/suggestions that Ben gave in [PR 75](https://github.com/SuperCowPowers/zat/pull/75) were well received. The PR itself had some issues with 'cruft' and other details but the core concepts were solid, so we borrowed those and made a new PR that is more aligned with the existing implementation. Thanks again to Ben for helping us improve the performance on large Bro/Zeek files.

**Test Data:**
Since conn.log is typically the most voluminous, we're going to use this 2.5 Gig conn.long file for our performance testing.

- <https://data.kitware.com/#item/58ebde398d777f16d095fd0e>

**Test Script:**
We're simply going to use the [zeek\_to\_pandas.py](https://github.com/SuperCowPowers/zat/blob/main/examples/zeek_to_pandas.py) in the examples directory for testing. We'll be using Python 3.7.

```
$ time python zeek_to_pandas.py ~/data/bro/conn.log
```

**Baseline:**
Our baseline for this testing will obviously be the existing repository functionality as it is.

**bhklimk PR:**
The PR from <https://github.com/bhklimk> shown here: [PR 75](https://github.com/SuperCowPowers/zat/pull/75)

**PR 76:**
A new PR focused specifically on memory/time improvements for large data frames.
[PR 76](https://github.com/SuperCowPowers/zat/pull/76)


## Performance Results

| Code         | Memory (peak) | Memory (DF)       | Total Time*  | Notes            |
|--------------|---------------|-------------------|--------------|------------------|
| Baseline     | ~34.6 GB      | 13.8 GB           | 8m 19s       |                  |
| bhklimk PR   | ~19 GB        | 18.62 -> 7.0 GB** | 5m 12s       |                  |
| PR 76+       | ~5.6 GB       | 3.8 GB            | 2m 57s       |                  |
| PR 76 (chunk)***| ~12 GB        | 11.8 GB           | 3m 51s       |                  |

\+ With 'usecols' the time and memory will be even less

\* Computing the 'deep memory' use of the large data frames added about 1 minute of time to all of the tests.

\*\* bhklimk PR builds a large data frame and then compresses it by converting the columns to categorical types.

*** Used the read_csv chunksize=1e6 parameter and then pd.concat the chunked dataframes (see observation 'Chunking' below)

## Observations
**Time:**
As noted in this issue <https://github.com/SuperCowPowers/zat/issues/23> the baseline construction of a data frame is inefficient, for large data frames this inefficiency plus the time wasted on memory paging/swapping starts to dominate the load time.

**Memory:**
As we've demonstrated in some of our notebooks examples, properly encoding categorical data will provide a significant memory reduction [Categorical Notebook](https://nbviewer.jupyter.org/github/SuperCowPowers/scp-labs/blob/main/notebooks/Categorical_Data_Guide.ipynb).

**Details:**
The proper conversion of 'time' to datetime and 'interval' to timedelta are taken care of by PR 76. Also the 'ts' field is properly set as the index of the dataframe.

**Chunking:**
So every Stack Overflow answer about reading in large dataframes uses a chunking approach, we obviously tried that first and it was a total fail on multiple dimensions.

1. **Size/Memory:** Chunking the dataframe into pieces and then immediately combining those pieces with pd.concat, is a bit like chopping up a log and then reassembling it. You end up with the same log. So since the final size in memory is a big factor in our 'optimization' this doesn't really help us much in theory and made things worse in practice (see item 3 below).
1. **Time:** The chunking + concat combine code took more time to execute than just simply reading in the whole dataframe.
1. **Memory (again):** Simple categorical types 'survived' the concat process, slightly more complex ones got punted down to the 'object' type which basically ruined the whole point of a compact dataframe that heavily engages categories. In particular 'proto' and 'local\_orig' remained categorical types, 'id.orig\_h', 'id.resp\_h', 'service', 'conn\_state', and 'history' did **not**. See detailed test output below.

**Note:** I'm happy to be wrong about any of these points, please replicate the test above and smack me with some science, I'll gladly eat some crow if it means we get better/faster dataframe construction :)

## Final Decision:
After Benjamin Klimkowski <https://github.com/bhklimk> and I both did some testing and discussion we've decided to use [PR 76](https://github.com/SuperCowPowers/zat/pull/76) (without 'chunking').

## Detailed Test Output
**Baseline**

```
(py37)$ time python zeek_to_pandas.py ~/data/bro/conn.log
Successfully monitoring /Users/briford/data/bro/conn.log...

[5 rows x 19 columns]
uid                        object
id.orig_h                  object
id.orig_p                   int64
id.resp_h                  object
id.resp_p                   int64
proto                      object
service                    object
duration          timedelta64[ns]
orig_bytes                  int64
resp_bytes                  int64
conn_state                 object
local_orig                   bool
missed_bytes                int64
history                    object
orig_pkts                   int64
orig_ip_bytes               int64
resp_pkts                   int64
resp_ip_bytes               int64
tunnel_parents             object

DF Shape: (22694356, 19)
DF Memory:
	 Index: 	     181.55 MB
	 uid: 	        1696.11 MB
	 id.orig_h: 	1623.26 MB
	 id.orig_p: 	 181.55 MB
	 id.resp_h: 	1608.96 MB
	 id.resp_p: 	 181.55 MB
	 proto: 	    1361.84 MB
	 service: 	    1318.07 MB
	 duration: 	     181.55 MB
	 orig_bytes: 	 181.55 MB
	 resp_bytes:     181.55 MB
	 conn_state: 	1352.43 MB
	 local_orig: 	  22.69 MB
	 missed_bytes:   181.55 MB
	 history: 	    1410.22 MB
	 orig_pkts: 	 181.55 MB
	 orig_ip_bytes:  181.55 MB
	 resp_pkts: 	 181.55 MB
	 resp_ip_bytes:  181.55 MB
	 tunnel_parents:1452.44 MB
DF Total: 13.84 GB

real	8m19.358s
user	6m55.156s
sys	    1m10.313s
```

**bhklimk PR**

```
(bhklimk-fix_for_issue_71)$ time python zeek_to_pandas.py ~/data/bro/conn.log
DF Shape: (22694356, 20)
DF Memory:
	 Index:           0.00 MB
	 ts:            181.55 MB
	 uid:          1696.11 MB
	 id.orig_h:    1623.26 MB
	 id.orig_p:     181.55 MB
	 id.resp_h:    1608.96 MB
	 id.resp_p:     181.55 MB
	 proto:        1361.84 MB
	 service:      1318.07 MB
	 duration:     1343.66 MB
	 orig_bytes:   1343.14 MB
	 resp_bytes:   1344.48 MB
	 conn_state:   1352.43 MB
	 local_orig:   1316.27 MB
	 missed_bytes:  181.55 MB
	 history:      1410.22 MB
	 orig_pkts:     181.55 MB
	 orig_ip_bytes: 181.55 MB
	 resp_pkts: 	181.55 MB
	 resp_ip_bytes: 181.55 MB
	 tunnel_parents:1452.44 MB
DF Total: 18.62 GB

uid                 object
id.orig_h         category
id.orig_p           uint16
id.resp_h         category
id.resp_p           uint16
proto             category
service           category
duration            object
orig_bytes          object
resp_bytes          object
conn_state        category
local_orig        category
missed_bytes      category
history           category
orig_pkts           uint64
orig_ip_bytes       uint64
resp_pkts           uint64
resp_ip_bytes       uint64
tunnel_parents    category

DF Shape: (22694356, 19)
DF Memory:
	 Index: 	181.55 MB
	 uid: 	1696.11 MB
	 id.orig_h: 	45.43 MB
	 id.orig_p: 	45.39 MB
	 id.resp_h: 	45.94 MB
	 id.resp_p: 	45.39 MB
	 proto: 	22.69 MB
	 service: 	22.70 MB
	 duration: 	1343.66 MB
	 orig_bytes: 	1343.14 MB
	 resp_bytes: 	1344.48 MB
	 conn_state: 	22.70 MB
	 local_orig: 	22.69 MB
	 missed_bytes: 	22.70 MB
	 history: 	45.45 MB
	 orig_pkts: 	181.55 MB
	 orig_ip_bytes: 	181.55 MB
	 resp_pkts: 	181.55 MB
	 resp_ip_bytes: 	181.55 MB
	 tunnel_parents: 	22.70 MB
DF Total: 7.00 GB

real	5m12.067s
user	4m53.237s
sys	0m18.816s
```

**PR 76**

```
uid                        object
id.orig_h                category
id.orig_p                  UInt16
id.resp_h                category
id.resp_p                  UInt16
proto                    category
service                  category
duration          timedelta64[ns]
orig_bytes                 UInt64
resp_bytes                 UInt64
conn_state               category
local_orig               category
missed_bytes               UInt64
history                  category
orig_pkts                  UInt64
orig_ip_bytes              UInt64
resp_pkts                  UInt64
resp_ip_bytes              UInt64
tunnel_parents           category
dtype: object
DF Shape: (22694356, 19)
DF Memory:
	 Index:         181.55 MB
	 uid:          1696.11 MB
	 id.orig_h:      45.43 MB
	 id.orig_p:      68.08 MB
	 id.resp_h:      45.94 MB
	 id.resp_p:      68.08 MB
	 proto:          22.69 MB
	 service:        22.70 MB
	 duration:      181.55 MB
	 orig_bytes:    204.25 MB
	 resp_bytes:    204.25 MB
	 conn_state:     22.70 MB
	 local_orig:     22.69 MB
	 missed_bytes:  204.25 MB
	 history:        45.45 MB
	 orig_pkts:     204.25 MB
	 orig_ip_bytes: 204.25 MB
	 resp_pkts:     204.25 MB
	 resp_ip_bytes: 204.25 MB
	 tunnel_parents: 22.70 MB
DF Total: 3.88 GB

real	2m57.822s
user	2m52.370s
sys	   0m6.031s
```

**PR 76 (with chunking)**

```
$ time python zeek_to_pandas.py /Users/briford/data/bro/conn.log

uid                        object
id.orig_h                  object
id.orig_p                  UInt16
id.resp_h                  object
id.resp_p                  UInt16
proto                    category
service                    object
duration          timedelta64[ns]
orig_bytes                 UInt64
resp_bytes                 UInt64
conn_state                 object
local_orig               category
missed_bytes               UInt64
history                    object
orig_pkts                  UInt64
orig_ip_bytes              UInt64
resp_pkts                  UInt64
resp_ip_bytes              UInt64
tunnel_parents             object

DF Shape: (22694356, 19)
DF Memory:
	 Index: 	181.55 MB
	 uid: 	1696.11 MB
	 id.orig_h: 	1623.26 MB
	 id.orig_p: 	68.08 MB
	 id.resp_h: 	1608.96 MB
	 id.resp_p: 	68.08 MB
	 proto: 	22.69 MB
	 service: 	745.42 MB
	 duration: 	181.55 MB
	 orig_bytes: 	204.25 MB
	 resp_bytes: 	204.25 MB
	 conn_state: 	1352.43 MB
	 local_orig: 	22.69 MB
	 missed_bytes: 	204.25 MB
	 history: 	1405.51 MB
	 orig_pkts: 	204.25 MB
	 orig_ip_bytes: 	204.25 MB
	 resp_pkts: 	204.25 MB
	 resp_ip_bytes: 	204.25 MB
	 tunnel_parents: 	1452.44 MB
DF Total: 11.86 GB

real	3m51.152s
user	3m45.320s
sys	0m6.254s

```
