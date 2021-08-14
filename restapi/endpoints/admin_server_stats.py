import os
import re
import shutil
from datetime import datetime

from plumbum import local

from restapi import decorators
from restapi.endpoints.schemas import StatsSchema, StatsType
from restapi.rest.definition import EndpointResource, Response
from restapi.services.authentication import Role, User


class AdminStats(EndpointResource):

    labels = ["helpers"]
    depends_on = ["AUTH_ENABLE"]
    private = True

    @decorators.auth.require_all(Role.ADMIN)
    @decorators.marshal_with(StatsSchema(), code=200)
    @decorators.endpoint(
        path="/admin/stats",
        summary="Retrieve stats from the server",
        responses={"200": "Stats retrieved"},
    )
    def get(self, user: User) -> Response:

        # This is the average system load calculated over a given period of time
        # of 1, 5 and 15 minutes.
        # In our case, we will show the load average over a period of 15 minutes.
        # The numbers returned by os.getloadavg() only make sense if
        # related to the number of CPU cores installed on the system.

        # Here we are converting the load average into percentage.
        # The higher the percentage the higher the load
        load_percentage = (100 * os.getloadavg()[-1]) / (os.cpu_count() or 1)

        vmstat = local["vmstat"]

        vmstat_out1 = vmstat().split("\n")
        vmstat_out1 = re.split(r"\s+", vmstat_out1[2])

        # convert list in dict
        vmstat_out1 = {k: v for k, v in enumerate(vmstat_out1)}

        # summarize disk statistics
        # vmstat_out2 = vmstat(["-D"]).split('\n')
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
        vmstat_out2 = vmstat(["-s", "-S", "M"]).split("\n")

        boot_time = datetime.fromtimestamp(int(vmstat_out2[24].strip().split(" ")[0]))

        # Disk usage
        # Get total disk size, used disk space, and free disk
        total, used, free = shutil.disk_usage("/")

        # Network latency
        # Here we will ping google at an interval of five seconds for five times
        # min response time, average response time, and the max response time.
        # ping = local["ping"]
        # ping_result = ping(["-c", "5", "google.com"]).split("\n")

        # ping_result = ping_result[-2].split("=")[-1].split("/")[:3]

        statistics: StatsType = {
            "system": {"boot_time": boot_time},
            "cpu": {
                # Get Physical and Logical CPU Count
                "count": os.cpu_count() or 0,
                "load_percentage": load_percentage,
                # System
                #     in: The number of interrupts per second, including the clock.
                #     cs: The number of context switches per second.
                # in = vm.get(11, 0)
                # cs = vm.get(12, 0)
                # CPU
                #     These are percentages of total CPU time.
                #     us: Time spent running non-kernel code. (user time and nice time)
                #     sy: Time spent running kernel code. (system time)
                #     id: Time spent idle.
                #     wa: Time spent waiting for IO.
                #     st: Time stolen from a virtual machine.
                "user": vmstat_out1.get(13, 0),
                "system": vmstat_out1.get(14, 0),
                "idle": vmstat_out1.get(15, 0),
                "wait": vmstat_out1.get(16, 0),
                "stolen": vmstat_out1.get(17, 0),
            },
            "ram": {
                "total": vmstat_out2[0].strip().split(" ")[0],
                "used": vmstat_out2[1].strip().split(" ")[0],
                "active": vmstat_out2[2].strip().split(" ")[0],
                "inactive": vmstat_out2[3].strip().split(" ")[0],
                "free": vmstat_out2[4].strip().split(" ")[0],
                "buffer": vmstat_out2[5].strip().split(" ")[0],
                "cache": vmstat_out2[6].strip().split(" ")[0],
            },
            "swap": {
                # Swap
                #     si: Amount of memory swapped in from disk (/s).
                #     so: Amount of memory swapped to disk (/s).
                "from_disk": vmstat_out1.get(7, 0),
                "to_disk": vmstat_out1.get(8, 0),
                "total": vmstat_out2[7].strip().split(" ")[0],
                "used": vmstat_out2[8].strip().split(" ")[0],
                "free": vmstat_out2[9].strip().split(" ")[0],
            },
            "disk": {
                "total_disk_space": total / 1024 ** 3,
                "used_disk_space": used / 1024 ** 3,
                "free_disk_space": free / 1024 ** 3,
                "occupacy": 100 * used / total,
            },
            "procs": {
                # Procs
                # r: The number of processes waiting for run time.
                # b: The number of processes in uninterruptible sleep.
                "waiting_for_run": vmstat_out1.get(1, 0),
                "uninterruptible_sleep": vmstat_out1.get(2, 0),
            },
            "io": {
                # IO
                #     bi: Blocks received from a block device (blocks/s).
                #     bo: Blocks sent to a block device (blocks/s).
                "blocks_received": vmstat_out1.get(9, 0),
                "blocks_sent": vmstat_out1.get(10, 0),
            },
            "network_latency": {
                # "min": ping_result[0].strip(),
                # "avg": ping_result[1].strip(),
                # "max": ping_result[2].strip(),
                "min": 0,
                "avg": 0,
                "max": 0,
            },
        }

        return self.response(statistics)
