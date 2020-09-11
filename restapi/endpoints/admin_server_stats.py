import os
import re
import shutil
from datetime import datetime

from plumbum import local

from restapi import decorators
from restapi.models import ISO8601UTC, Schema, fields
from restapi.rest.definition import EndpointResource
from restapi.services.authentication import Role


class StatsSchema(Schema):
    boot_time = fields.DateTime(format=ISO8601UTC)
    cpu = fields.Nested(
        {
            "count": fields.Int(),
            "load": fields.Decimal(places=2),
            "user": fields.Int(),
            "system": fields.Int(),
            "idle": fields.Int(),
            "wait": fields.Int(),
            "stolen": fields.Int(),
        }
    )
    ram = fields.Nested(
        {
            "total": fields.Int(),
            "used": fields.Int(),
            "active": fields.Int(),
            "inactive": fields.Int(),
            "buffer": fields.Int(),
            "free": fields.Int(),
            "cache": fields.Int(),
        }
    )

    swap = fields.Nested(
        {
            "from_disk": fields.Int(),
            "to_disk": fields.Int(),
            "total": fields.Int(),
            "used": fields.Int(),
            "free": fields.Int(),
        }
    )

    disk = fields.Nested(
        {
            "total_disk_space": fields.Decimal(places=2),
            "used_disk_space": fields.Decimal(places=2),
            "free_disk_space": fields.Decimal(places=2),
            "occupacy": fields.Decimal(places=2),
        }
    )

    procs = fields.Nested(
        {"waiting_for_run": fields.Int(), "uninterruptible_sleep": fields.Int()}
    )

    io = fields.Nested({"blocks_received": fields.Int(), "blocks_sent": fields.Int()})

    network_latency = fields.Nested(
        {
            "min": fields.Decimal(places=2),
            "max": fields.Decimal(places=2),
            "avg": fields.Decimal(places=2),
        }
    )


class AdminStats(EndpointResource):

    labels = ["helpers"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(StatsSchema(), code=200)
    @decorators.endpoint(
        path="/admin/stats",
        summary="Retrieve stats from the server",
        responses={"200": "Stats retrieved"},
    )
    def get(self):
        statistics = {
            "cpu": {},
            "ram": {},
            "swap": {},
            "disk": {},
            "procs": {},
            "io": {},
            "network_latency": {},
        }

        # Get Physical and Logical CPU Count
        statistics["cpu"]["count"] = os.cpu_count()

        # This is the average system load calculated over a given period of time
        # of 1, 5 and 15 minutes.
        # In our case, we will show the load average over a period of 15 minutes.
        # The numbers returned by os.getloadavg() only make sense if
        # related to the number of CPU cores installed on the system.

        # Here we are converting the load average into percentage.
        # The higher the percentage the higher the load
        statistics["cpu"]["load"] = (100 * os.getloadavg()[-1]) / os.cpu_count()

        # # Total amount of RAM
        # grep = local["grep"]
        # regexp = r"MemTotal:\s+(\d+) kB"

        # if m := re.search(regexp, grep(["MemTotal", "/proc/meminfo"])):
        #     statistics["ram"]["total"] = m.group(1)

        vmstat = local["vmstat"]
        vm = vmstat().split("\n")
        vm = re.split(r"\s+", vm[2])

        # convert list in dict
        vm = {k: v for k, v in enumerate(vm)}

        # Procs
        # r: The number of processes waiting for run time.
        # b: The number of processes in uninterruptible sleep.
        statistics["procs"]["waiting_for_run"] = vm.get(1, "N/A")
        statistics["procs"]["uninterruptible_sleep"] = vm.get(2, "N/A")

        # Swap
        #     si: Amount of memory swapped in from disk (/s).
        #     so: Amount of memory swapped to disk (/s).
        statistics["swap"]["from_disk"] = vm.get(7, "N/A")
        statistics["swap"]["to_disk"] = vm.get(8, "N/A")

        # IO
        #     bi: Blocks received from a block device (blocks/s).
        #     bo: Blocks sent to a block device (blocks/s).
        statistics["io"]["blocks_received"] = vm.get(9, "N/A")
        statistics["io"]["blocks_sent"] = vm.get(10, "N/A")
        # System
        #     in: The number of interrupts per second, including the clock.
        #     cs: The number of context switches per second.
        # in = vm.get(11, "N/A")
        # cs = vm.get(12, "N/A")

        # CPU
        #     These are percentages of total CPU time.
        #     us: Time spent running non-kernel code. (user time, including nice time)
        #     sy: Time spent running kernel code. (system time)
        #     id: Time spent idle.
        #     wa: Time spent waiting for IO.
        #     st: Time stolen from a virtual machine.

        statistics["cpu"]["user"] = vm.get(13, "N/A")
        statistics["cpu"]["system"] = vm.get(14, "N/A")
        statistics["cpu"]["idle"] = vm.get(15, "N/A")
        statistics["cpu"]["wait"] = vm.get(16, "N/A")
        statistics["cpu"]["stolen"] = vm.get(17, "N/A")

        # summarize disk statistics
        # vm = vmstat(["-D"]).split('\n')
        # Example:
        #       22 disks
        #        0 partitions
        #   273820 total reads
        #    63034 merged reads
        # 27787446 read sectors
        #  2395193 milli reading
        #   116450 writes
        #   438666 merged writes
        #  4467248 written sectors
        # 15377932 milli writing
        #        0 inprogress IO
        #     1412 milli spent IO

        # event counter statistics
        vm = vmstat(["-s", "-S", "M"]).split("\n")

        statistics["ram"]["total"] = vm[0].strip().split(" ")[0]
        statistics["ram"]["used"] = vm[1].strip().split(" ")[0]
        statistics["ram"]["active"] = vm[2].strip().split(" ")[0]
        statistics["ram"]["inactive"] = vm[3].strip().split(" ")[0]
        statistics["ram"]["free"] = vm[4].strip().split(" ")[0]
        statistics["ram"]["buffer"] = vm[5].strip().split(" ")[0]
        statistics["ram"]["cache"] = vm[6].strip().split(" ")[0]
        statistics["swap"]["total"] = vm[7].strip().split(" ")[0]
        statistics["swap"]["used"] = vm[8].strip().split(" ")[0]
        statistics["swap"]["free"] = vm[9].strip().split(" ")[0]
        # 31043968 non-nice user cpu ticks
        # 107729 nice user cpu ticks
        # 7319284 system cpu ticks
        # 46052009 idle cpu ticks
        # 49240 IO-wait cpu ticks
        # 0 IRQ cpu ticks
        # 232548 softirq cpu ticks
        # 0 stolen cpu ticks
        # 18753270 pages paged in
        # 99473392 pages paged out
        # 25168 pages swapped in
        # 100386 pages swapped out
        # 793916005 interrupts
        # 2266434254 CPU context switches
        statistics["boot_time"] = datetime.fromtimestamp(
            int(vm[24].strip().split(" ")[0])
        )
        # 742942 forks

        # Disk usage
        # Get total disk size, used disk space, and free disk
        total, used, free = shutil.disk_usage("/")
        statistics["disk"]["total_disk_space"] = total / 1024 ** 3
        statistics["disk"]["used_disk_space"] = used / 1024 ** 3
        statistics["disk"]["free_disk_space"] = free / 1024 ** 3
        statistics["disk"]["occupacy"] = 100 * used / total

        # Network latency
        # Here we will ping google at an interval of five seconds for five times
        # min response time, average response time, and the max response time.
        ping = local["ping"]
        ping_result = ping(["-c", "5", "google.com"]).split("\n")

        ping_result = ping_result[-2].split("=")[-1].split("/")[:3]
        statistics["network_latency"] = dict(
            {
                "min": ping_result[0].strip(),
                "avg": ping_result[1].strip(),
                "max": ping_result[2].strip(),
            }
        )
        return self.response(statistics)
