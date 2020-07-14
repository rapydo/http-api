import datetime

from restapi.tests import API_URI, BaseTests


class TestApp(BaseTests):
    def test_admin_stats(self, client):

        r = client.get(f"{API_URI}/admin/stats")
        assert r.status_code == 401

        headers, _ = self.do_login(client, None, None)

        r = client.get(f"{API_URI}/admin/stats", headers=headers)
        assert r.status_code == 200
        stats = self.get_content(r)

        # ### BOOT TIME ###
        assert "boot_time" in stats
        d = datetime.strptime(stats["boot_time"], "%Y-%m-%dT%H:%M:%S")
        assert d < datetime.now()

        # ### CPU ###
        assert "cpu" in stats

        assert "count" in stats["cpu"]
        assert stats["cpu"]["count"] > 0

        assert "idle" in stats["cpu"]
        assert stats["cpu"]["idle"] >= 0
        assert stats["cpu"]["idle"] <= 100

        assert "load" in stats["cpu"]
        assert stats["cpu"]["load"] >= 0
        assert stats["cpu"]["load"] <= 100

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
        assert stats["disk"]["total_disk_space"] > 0

        assert "free_disk_space" in stats["disk"]
        assert stats["disk"]["free_disk_space"] >= 0
        assert stats["disk"]["free_disk_space"] < stats["disk"]["total_disk_space"]

        assert "used_disk_space" in stats["disk"]
        assert stats["disk"]["used_disk_space"] >= 0
        assert stats["disk"]["used_disk_space"] < stats["disk"]["total_disk_space"]

        s = stats["disk"]["free_disk_space"] + stats["disk"]["used_disk_space"]
        assert stats["disk"]["total_disk_space"] == s

        assert "occupacy" in stats["disk"]
        assert stats["disk"]["occupacy"] >= 0
        assert stats["disk"]["occupacy"] <= 100

        p = stats["disk"]["used_disk_space"] / stats["disk"]["total_disk_space"]
        assert stats["disk"]["occupacy"] == round(p, 2)

        # ### IO ###
        assert "io" in stats

        assert "blocks_received" in stats["io"]
        assert stats["io"]["blocks_received"] >= 0

        assert "blocks_sent" in stats["io"]
        assert stats["io"]["blocks_sent"] >= 0

    #     # ### NETWORK ###
    #     assert "network_latency" in stats
    #     "avg": 31.79,
    #     "max": 50.32,
    #     "min": 21.64
    #     # ### PROCS ###
    #     assert "procs" in stats
    #     "uninterruptible_sleep": 0,
    #     "waiting_for_run": 0
    #     # ### RAM ###
    #     assert "ram" in stats
    #     "active": 11191,
    #     "buffer": 552,
    #     "cache": 3938,
    #     "free": 987,
    #     "inactive": 2333,
    #     "total": 15894,
    #     "used": 10416
    #     # ### SWAP ###
    #     assert "swap" in stats
    # "": {
    #     "free": 1947,
    #     "from_disk": 0,
    #     "to_disk": 1,
    #     "total": 2047,
    #     "used": 100
    # }
