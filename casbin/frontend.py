import json


def casbin_js_get_permission_for_user(e, user):
    model = e.get_model()
    m = {}
    m["m"] = model.to_text()
    policies = []
    for p_type in model["p"].keys():
        policy = model.get_policy("p", p_type)
        for p in policy:
            policies.append([p_type] + p)
    m["p"] = policies
    return json.dumps(m)
