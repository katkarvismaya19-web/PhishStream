# Resume bullets (replace numbers with your own measured ones if you re-run on real data)

**PhishStream: real-time phishing detection and threat analytics** · Python, Kafka, Spark Structured Streaming, Spark MLlib, Redis, FastAPI, Docker

- Built a streaming detection pipeline (Kafka → Spark Structured Streaming → Redis → FastAPI/WebSocket) that scores ~9,400 URL events/sec per core at 1.3 ms p95, combining a Bloom-filter threat lookup with an ML model for unseen phishing.
- Trained a gradient-boosting URL classifier on 28 lexical features with a time-based split; on future campaigns it reached 99.3% precision / 97.9% recall, where a blacklist alone caught 0.1%.
- Implemented streaming sketches (DGIM, HyperLogLog, Count-Min, reservoir sampling), each benchmarked against exact baselines, e.g. ~2% distinct-count error in 4 KB vs an 89 MB exact set.
- Built a distributed Bloom filter on Spark (partition-level filters merged by bitwise OR), verified bit-for-bit against the single-machine build.
- Discovered phishing campaigns with MinHash + LSH (99.6% of pairwise comparisons skipped) and ranked shared hosting infrastructure with PageRank on a 50K-node graph; mined lure patterns with Apriori / PCY / SON.
