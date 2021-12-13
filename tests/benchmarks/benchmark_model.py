import os
import casbin


def raw_enforce(sub, obj, act):
    policy = [["alice", "data1", "read"], ["bob", "data2", "write"]]
    for rule in policy:
        if sub == rule[0] and obj == rule[1] and act == rule[2]:
            return True

    return False


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)


def get_enforcer(model=None, adapter=None):
    return casbin.Enforcer(
        model,
        adapter,
    )


def test_benchmark_raw(benchmark):
    @benchmark
    def benchmark_raw():
        raw_enforce("alice", "data1", "read")


def test_benchmark_basic_model(benchmark):
    e = get_enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))

    @benchmark
    def benchmark_basic_model():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

    @benchmark
    def benchmark_rbac_model():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model_small(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies(
        {("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(100)}
    )
    e.add_grouping_policies(
        {("user" + str(i), "group" + str(int(i / 10))) for i in range(1000)}
    )

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_medium(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies(
        {("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(1000)}
    )
    e.add_grouping_policies(
        {("user" + str(i), "group" + str(int(i / 10))) for i in range(10000)}
    )

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_large(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies(
        {("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(10000)}
    )
    e.add_grouping_policies(
        {("user" + str(i), "group" + str(int(i / 10))) for i in range(100000)}
    )

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_with_resource_roles(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_resource_roles_model.conf"),
        get_examples("rbac_with_resource_roles_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_model_with_resource_roles():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model_with_domains(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_domains_model.conf"),
        get_examples("rbac_with_domains_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_model_with_domains():
        e.enforce("alice", "domain1", "data1", "read")


def test_benchmark_abac_model(benchmark):
    e = get_enforcer(get_examples("abac_model.conf"))
    sub = "alice"
    obj = {"Owner": "alice", "id": "data1"}

    @benchmark
    def benchmark_abac_model():
        e.enforce(sub, obj, "read")


def test_benchmark_rbac_with_deny(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_deny_model.conf"),
        get_examples("rbac_with_deny_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_with_deny():
        e.enforce("alice", "data1", "read")


def test_benchmark_prioriry(benchmark):
    e = get_enforcer(
        get_examples("priority_model.conf"), get_examples("priority_policy.csv")
    )

    @benchmark
    def benchmark_rbac_with_deny():
        e.enforce("alice", "data1", "read")


def test_benchmark_keymatch(benchmark):
    e = get_enforcer(
        get_examples("keymatch_model.conf"), get_examples("keymatch_policy.csv")
    )

    @benchmark
    def benchmark_keymatch():
        e.enforce("alice", "/alice_data/resource1", "GET")
