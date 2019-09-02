## Performance on large dataframes
We have several outstanding issues for needed improvements to support the ingestion and processing of large Bro/Zeek log files.

- <https://github.com/SuperCowPowers/bat/issues/23>
- <https://github.com/SuperCowPowers/bat/issues/71>

There's also a PR from <https://github.com/bhklimk> with some good suggestions.

Big thanks to Benjamin Klimkowski <https://github.com/bhklimk>. The ideas/suggestions that Ben gave in [PR 75](https://github.com/SuperCowPowers/bat/pull/75) were well received. The PR itself has issues with 'cruft' and some of the details but the core concepts are solid, so we're going to borrow those and we've made a new PR that is more aligned with the existing implementation. Thanks again to Ben for helping us improve the performance on large Bro/Zeek files.

**Test Data:**
Since conn.log is typically the most voluminous, we're going to use this 2.5 Gig conn.long file for our performance testing.

- <https://data.kitware.com/#item/58ebde398d777f16d095fd0e>

**Test Script:**
We're simply going to use the [bro\_to\_pandas.py](https://github.com/SuperCowPowers/bat/blob/master/examples/bro_to_pandas.py) in the examples directory for testing. We'll be using Python 3.7.

```
$ time python bro_to_pandas.py ~/data/bro/conn.log 
```

**Baseline:**
Our baseline for this testing will obviously be the existing repository functionality as it is.

**bhklimk PR:**
The PR from <https://github.com/bhklimk> shown here: [PR 75](https://github.com/SuperCowPowers/bat/pull/75)

**PR 76:**
A new PR focused specifically on memory/time improvements for large data frames.

## Performance Results

| Code       | Memory (peak) | Memory (DF)       | Total Time*  | Notes            |
|------------|---------------|-------------------|--------------|------------------|
| Baseline   | ~34.6 GB      | 13.8 GB           | 8m 19s       |                  |
| bhklimk PR | ~19 GB        | 18.62 -> 7.0 GB** | 5m 12s       |                  |
| PR 76.     | ~5.6 GB       | 3.7 GB            | 1m 24s       | WIP              |

\* Computing the 'deep memory' use of the large data frames added about more time to all of the tests.

\*\* bhklimk PR builds a large data frame and then compresses it by converting the columns to categorical types.

## Observations
**Time:**
As noted in this issue <https://github.com/SuperCowPowers/bat/issues/23> the baseline construction of a data frame is inefficient, for large data frames this inefficiency plus the time wasted on memory paging/swapping starts to dominate the load time.

**Memory:**
As we've demonstrated in some of our notebooks examples, properly encoding categorical data will provide a significant memory reduction [Categorical Notebook](https://nbviewer.jupyter.org/github/SuperCowPowers/scp-labs/blob/master/notebooks/Categorical_Data_Guide.ipynb).

## Detailed Test Output
**Baseline**

```
(py37)$ time python bro_to_pandas.py ~/data/bro/conn.log 
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
(bhklimk-fix_for_issue_71)$ time python bro_to_pandas.py ~/data/bro/conn.log 
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
(py37) $ time python bro_to_pandas.py ~/data/bro/conn.log 
uid                 object
id.orig_h         category
id.orig_p           UInt16
id.resp_h         category
id.resp_p           UInt16
proto             category
service           category
duration           float64
orig_bytes         float64
resp_bytes         float64
conn_state        category
local_orig        category
missed_bytes       float64
history           category
orig_pkts          float64
orig_ip_bytes      float64
resp_pkts          float64
resp_ip_bytes      float64
tunnel_parents    category
dtype: object
DF Shape: (22694356, 19)
DF Memory:
	 Index: 	181.55 MB
	 uid: 	1696.11 MB
	 id.orig_h: 	45.43 MB
	 id.orig_p: 	68.08 MB
	 id.resp_h: 	45.94 MB
	 id.resp_p: 	68.08 MB
	 proto: 	22.69 MB
	 service: 	22.70 MB
	 duration: 	181.55 MB
	 orig_bytes: 	181.55 MB
	 resp_bytes: 	181.55 MB
	 conn_state: 	22.70 MB
	 local_orig: 	22.69 MB
	 missed_bytes: 	181.55 MB
	 history: 	45.45 MB
	 orig_pkts: 	181.55 MB
	 orig_ip_bytes: 	181.55 MB
	 resp_pkts: 	181.55 MB
	 resp_ip_bytes: 	181.55 MB
	 tunnel_parents: 	22.70 MB
DF Total: 3.72 GB

real	1m27.572s
user	1m22.787s
sys	0m5.180s
```

