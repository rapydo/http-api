from datetime import datetime

from restapi.env import Env
from restapi.tests import API_URI, BaseTests, FlaskClient
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_admin_stats(self, client: FlaskClient) -> None:
        if not Env.get_bool("AUTH_ENABLE"):
            log.warning("Skipping admin/stats tests")
            return

        r = client.get(f"{API_URI}/admin/stats")
        assert r.status_code == 401

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/stats", headers=headers)
        assert r.status_code == 200
        stats = self.get_content(r)
        assert isinstance(stats, dict)

        # ### BOOT TIME ###
        assert "system" in stats
        assert "boot_time" in stats["system"]
        d = datetime.strptime(stats["system"]["boot_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
        assert d < datetime.now()

        # ### CPU ###
        assert "cpu" in stats

        assert "count" in stats["cpu"]
        assert stats["cpu"]["count"] > 0

        assert "idle" in stats["cpu"]
        assert stats["cpu"]["idle"] >= 0
        assert stats["cpu"]["idle"] <= 100

        assert "load_percentage" in stats["cpu"]
        assert float(stats["cpu"]["load_percentage"]) >= 0
        # Originally it was <= 100, but sometimes the GHA VMs are overloaded
        # and the cpu usage is greater than 100%
        assert float(stats["cpu"]["load_percentage"]) <= 150

        assert "stolen" in stats["cpu"]
        assert stats["cpu"]["stolen"] >= 0
        assert stats["cpu"]["stolen"] <= 100

        assert "system" in stats["cpu"]
        assert stats["cpu"]["system"] >= 0
        assert stats["cpu"]["system"] <= 100

        assert "user" in stats["cpu"]
        assert stats["cpu"]["user"] >= 0
        assert stats["cpu"]["user"] <= 100

        assert "wait" in stats["cpu"]
        assert stats["cpu"]["wait"] >= 0
        assert stats["cpu"]["wait"] <= 100

        # ### DISK ###
        assert "disk" in stats

        assert "total_disk_space" in stats["disk"]
        assert "free_disk_space" in stats["disk"]
        assert "used_disk_space" in stats["disk"]
        assert "occupacy" in stats["disk"]

        stats["disk"]["total_disk_space"] = float(stats["disk"]["total_disk_space"])
        stats["disk"]["free_disk_space"] = float(stats["disk"]["free_disk_space"])
        stats["disk"]["used_disk_space"] = float(stats["disk"]["used_disk_space"])
        stats["disk"]["occupacy"] = float(stats["disk"]["occupacy"])

        assert stats["disk"]["total_disk_space"] > 0

        assert stats["disk"]["free_disk_space"] >= 0
        assert stats["disk"]["free_disk_space"] < stats["disk"]["total_disk_space"]

        assert stats["disk"]["used_disk_space"] >= 0
        assert stats["disk"]["used_disk_space"] < stats["disk"]["total_disk_space"]

        s = stats["disk"]["free_disk_space"] + stats["disk"]["used_disk_space"]
        assert abs(stats["disk"]["total_disk_space"] - s) < 0.5

        assert stats["disk"]["occupacy"] >= 0
        assert stats["disk"]["occupacy"] <= 100

        p = stats["disk"]["used_disk_space"] / stats["disk"]["total_disk_space"]
        assert abs(stats["disk"]["occupacy"] - round(100 * p, 2)) < 0.5

        # ### IO ###
        assert "io" in stats

        assert "blocks_received" in stats["io"]
        assert stats["io"]["blocks_received"] >= 0

        assert "blocks_sent" in stats["io"]
        assert stats["io"]["blocks_sent"] >= 0

        # ### NETWORK ###
        assert "network_latency" in stats

        assert "min" in stats["network_latency"]
        assert "avg" in stats["network_latency"]
        assert "max" in stats["network_latency"]

        stats["network_latency"]["min"] = float(stats["network_latency"]["min"])
        stats["network_latency"]["avg"] = float(stats["network_latency"]["avg"])
        stats["network_latency"]["max"] = float(stats["network_latency"]["max"])

        assert stats["network_latency"]["min"] >= 0
        assert stats["network_latency"]["min"] <= stats["network_latency"]["avg"]
        assert stats["network_latency"]["min"] <= stats["network_latency"]["max"]

        assert stats["network_latency"]["avg"] >= 0
        assert stats["network_latency"]["avg"] >= stats["network_latency"]["min"]
        assert stats["network_latency"]["avg"] <= stats["network_latency"]["max"]

        assert stats["network_latency"]["max"] >= 0
        assert stats["network_latency"]["max"] >= stats["network_latency"]["min"]
        assert stats["network_latency"]["max"] >= stats["network_latency"]["avg"]

        # ### PROCS ###
        assert "procs" in stats

        assert "uninterruptible_sleep" in stats["procs"]
        assert stats["procs"]["uninterruptible_sleep"] >= 0

        assert "waiting_for_run" in stats["procs"]
        assert stats["procs"]["waiting_for_run"] >= 0

        # ### RAM ###
        assert "ram" in stats

        assert "total" in stats["ram"]
        assert stats["ram"]["total"] >= 0

        assert "used" in stats["ram"]
        assert stats["ram"]["used"] >= 0
        assert stats["ram"]["used"] <= stats["ram"]["total"]

        assert "active" in stats["ram"]
        assert stats["ram"]["active"] >= 0
        assert stats["ram"]["active"] <= stats["ram"]["total"]

        assert "buffer" in stats["ram"]
        assert stats["ram"]["buffer"] >= 0
        assert stats["ram"]["buffer"] <= stats["ram"]["total"]

        assert "cache" in stats["ram"]
        assert stats["ram"]["cache"] >= 0
        assert stats["ram"]["cache"] <= stats["ram"]["total"]

        assert "free" in stats["ram"]
        assert stats["ram"]["free"] >= 0
        assert stats["ram"]["free"] <= stats["ram"]["total"]

        assert "inactive" in stats["ram"]
        assert stats["ram"]["inactive"] >= 0
        assert stats["ram"]["inactive"] <= stats["ram"]["total"]

        # ### SWAP ###
        assert "swap" in stats

        assert "total" in stats["swap"]
        assert stats["swap"]["total"] >= 0

        assert "free" in stats["swap"]
        assert stats["swap"]["free"] >= 0
        assert stats["swap"]["free"] <= stats["swap"]["total"]

        assert "used" in stats["swap"]
        assert stats["swap"]["used"] >= 0
        assert stats["swap"]["used"] <= stats["swap"]["total"]

        assert "from_disk" in stats["swap"]
        assert stats["swap"]["from_disk"] >= 0

        assert "to_disk" in stats["swap"]
        assert stats["swap"]["to_disk"] >= 0
