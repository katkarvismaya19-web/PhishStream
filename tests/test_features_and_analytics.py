from phishstream.analytics.frequent_itemsets import apriori_pairs, pcy_pairs
from phishstream.analytics.pagerank import pagerank
from phishstream.features.url_features import FEATURE_NAMES, explain, extract, registered_domain


def test_feature_vector_shape():
    assert len(extract("http://sbi-kyc12.xyz/login")) == len(FEATURE_NAMES)


def test_explain_flags_obvious_phish_but_not_official():
    assert explain("http://sbi-kyc-update12.xyz/login")
    assert explain("https://onlinesbi.sbi/") == []


def test_registered_domain():
    assert registered_domain("a.b.example.co.in") == "example.co.in"
    assert registered_domain("x.sbi-kyc.xyz") == "sbi-kyc.xyz"


def test_pcy_matches_apriori():
    baskets = [frozenset(b) for b in (["a", "b", "c"], ["a", "b"], ["a", "c"], ["b", "c"], ["a", "b", "d"]) * 20]
    _, ap, _, _ = apriori_pairs(baskets, 30)
    pcy, _, _ = pcy_pairs(baskets, 30, n_buckets=7)
    assert set(ap) == set(pcy)


def test_pagerank_hub_wins_and_sums_to_one():
    edges = [(f"d{i}", "hub") for i in range(20)] + [("d0", "d1")]
    r, _, _ = pagerank(edges)
    assert max(r, key=r.get) == "hub"
    assert abs(sum(r.values()) - 1) < 1e-6
