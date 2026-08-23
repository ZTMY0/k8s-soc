#!/usr/bin/env python3
# encoding: utf-8
import os
import subprocess
import urllib.request
import urllib.parse
from cortexutils.responder import Responder

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": CHAT_ID, "text": text}).encode()
    try:
        urllib.request.urlopen(url, data=data, timeout=10)
    except Exception:
        pass


class K8sIsolate(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.namespace = self.get_param("config.namespace", "default")

    def run(self):
        Responder.run(self)

        pod_name = self.get_param("data", None, "Pod name is missing.").replace("pod:", "")

        get_label_cmd = [
            "kubectl", "get", "pod", pod_name,
            "-n", self.namespace,
            "-o", "jsonpath={.metadata.labels.app}"
        ]
        try:
            app_label = subprocess.check_output(get_label_cmd, stderr=subprocess.STDOUT).decode().strip()
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to get pod label: {e.output.decode()}")
            return

        if not app_label:
            self.error(f"Pod {pod_name} has no 'app' label, cannot build NetworkPolicy selector.")
            return

        policy_name = f"isolate-{pod_name}"
        network_policy = f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {policy_name}
  namespace: {self.namespace}
spec:
  podSelector:
    matchLabels:
      app: {app_label}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
"""

        apply_cmd = ["kubectl", "apply", "-f", "-"]
        try:
            result = subprocess.run(
                apply_cmd,
                input=network_policy.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            )
            output = result.stdout.decode()
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to apply NetworkPolicy: {e.output.decode()}")
            return

        send_telegram(
            f"🔒 RESPONDER ACTION\nPod isolated: {pod_name}\n"
            f"Namespace: {self.namespace}\nPolicy: {policy_name}\n"
            f"All ingress/egress traffic blocked."
        )

        self.report({
            "message": f"Pod {pod_name} isolated via NetworkPolicy {policy_name}",
            "kubectl_output": output
        })

    def operations(self, raw):
        return [self.build_operation("AddTagToCase", tag="k8s-isolated")]


if __name__ == "__main__":
    K8sIsolate().run()
