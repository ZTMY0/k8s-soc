#!/usr/bin/env python3
# encoding: utf-8

import subprocess
from cortexutils.responder import Responder


class IPBlockResponder(Responder):
    def __init__(self):
        Responder.__init__(self)
        # dataType-specific field: for an "ip" observable, Cortex passes it as data
        self.ip = self.get_param("data", None, "No IP provided")

    def run(self):
        Responder.run(self)

        try:
            # Block the IP at the firewall (INPUT chain, drop all inbound traffic from it)
            cmd = ["iptables", "-A", "INPUT", "-s", self.ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                self.error(f"iptables command failed: {result.stderr.strip()}")
                return

            self.report({
                "message": f"Blocked IP {self.ip} via iptables DROP rule",
                "ip": self.ip,
                "action": "blocked"
            })

        except Exception as e:
            self.error(f"Failed to block IP {self.ip}: {str(e)}")

    def operations(self, raw):
        return [self.build_operation("AddTagToArtifact", tag="blocked:iptables")]


if __name__ == "__main__":
    IPBlockResponder().run()
