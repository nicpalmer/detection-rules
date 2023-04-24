import os
import json
import requests
import toml
from uuid import uuid4

kbnuser = os.environ["DR_KIBANA_USER"]
kbnpwd = os.environ["DR_KIBANA_PASSWORD"]
kburl = os.environ["DR_KIBANA_URL"]


def make_request(url, data, kbnuser, kbnpwd):
    print("Top")
    return requests.post(
        url=url,
        json=data,
        headers={
            "Content-Type": "application/json",
            "kbn-xsrf": str(uuid4())
        },
        auth=(kbnuser, kbnpwd)
    )


def create_rules(createbody, kbnuser, kbnpwd):
    try:
        print("middle")
        resp = make_request("{}/api/detection_engine/rules/_bulk_create".format(kburl), createbody, kbnuser, kbnpwd)
        resp.raise_for_status()

        for response in resp.json():
            if response["statusCode"] in range(400, 599):
                print(resp.json())
                print("=====================================================================")
                print(createbody)
                raise ValueError("Failed to create rule")
    except Exception as err:
        print("Exception: {}".format(err))
        raise ValueError("Failed to create rule")


def get_custom_rules():
    custom_rules = []
    for root, dirs, files in os.walk("rules/"):
        if root.startswith("rules/custom"):
            for file in files:
                custom_rules.append(os.path.join(root, file))
    return custom_rules


def parse_toml_rules(custom_rules):
    toml_rules = []
    for rulefile in custom_rules:
        try:
            with open(rulefile, "r") as f:
                rule = f.read()
                t_rule = toml.loads(rule)
                toml_rules.append(t_rule)
        except Exception as err:
            print("Failed to parse {} with error: {}".format(rulefile, err))
    return toml_rules


def get_updatebody(toml_rules):
    updatebody = []
    for r in toml_rules:
        rule = r["rule"]
        if "rule_id" in rule:
            updatebody.append(rule)
    return updatebody


def main():
    custom_rules = get_custom_rules()
    toml_rules = parse_toml_rules(custom_rules)
    updatebody = get_updatebody(toml_rules)
    if len(updatebody) > 0:
        resp = make_request("{}/api/detection_engine/rules/_bulk_update".format(kburl), updatebody, kbnuser, kbnpwd)
        response = resp.json()

        if "error" in response:
            print(response["message"])
            exit(1)

        createbody = []
        for rule_resp in resp.json():
            if "error" in rule_resp and "not found" in rule_resp["error"]["message"]:
                print(rule_resp["error"]["message"])
                for r in updatebody:
                    if r["rule_id"] in rule_resp["error"]["message"]:
                        createbody.append(r)

        created = False
        if not created:
            try:
                create_rules(createbody, kbnuser, kbnpwd)
            except Exception:
                pass
            else:
                created = True


if __name__ == "__main__":
    main()
