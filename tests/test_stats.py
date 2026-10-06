from whetstone.stats import exact_ci, fisher_exact_two_sided, rate, wilson


def test_exact_ci_zero_of_n_matches_rule_of_three_style_bound():
    lo, hi = exact_ci(0, 165)
    assert lo == 0.0 and 0.021 < hi < 0.023   # README: about 2.2% for 0/165


def test_exact_ci_known_value():
    lo, hi = exact_ci(5, 20)                  # Clopper-Pearson reference: 0.0866 .. 0.4910
    assert abs(lo - 0.0866) < 0.001 and abs(hi - 0.4910) < 0.001


def test_exact_ci_edges():
    assert exact_ci(15, 15)[1] == 1.0 and exact_ci(0, 0) == [0.0, 1.0]


def test_wilson_contains_point_and_is_inside_exact_for_mid_rates():
    lo, hi = wilson(5, 20)
    assert lo < 0.25 < hi
    elo, ehi = exact_ci(5, 20)
    assert elo <= lo and hi <= ehi


def test_rate_shape():
    r = rate(2, 15)
    assert set(r) == {"k", "n", "rate", "wilson95", "exact95"} and r["rate"] == 0.1333


def test_fisher_known_value():
    assert abs(fisher_exact_two_sided(8, 15, 2, 15) - 0.0502) < 0.0005
    assert fisher_exact_two_sided(0, 15, 0, 15) == 1.0
