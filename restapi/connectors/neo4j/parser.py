import csv
from typing import Any, Dict, List

from restapi.config import IMPORT_PATH
from restapi.connectors import neo4j
from restapi.utilities.logs import log


class DataDump:
    def __init__(self, filename: str, fields: List[str]) -> None:

        for f in fields:
            if ":" not in f:
                raise ValueError(
                    f"Wrong field syntax, type is missing in {f}. Expected {f}:TYPE. "
                    "Supported types: string,int,float"
                )

        # This will be used by the backend to write the file
        self.filepath = IMPORT_PATH.joinpath(filename)
        # This will be used by neo4j to read the file
        self.filename = filename
        self.cache: Dict[str, bool] = {}
        self.fields = fields
        self.counter = 0

        with open(self.filepath, "w+") as out_handle:
            tsv_node_writer = csv.writer(out_handle, delimiter="\t")
            fields_without_types: List[str] = []
            for f in fields:
                fields_without_types.append(f.split(":")[0])
            tsv_node_writer.writerow(fields_without_types)

        self.handle = open(self.filepath, "a+")
        self.writer = csv.writer(self.handle, delimiter="\t")

    @property
    def count(self) -> int:
        return self.counter + len(self.cache)

    def flush_cache(self) -> None:
        self.counter += len(self.cache)
        self.cache.clear()

    def clean(self) -> None:
        self.flush_cache()
        self.close()
        self.filepath.unlink()

    def print_line(self, args: Any) -> None:

        for a in args:
            if a is None:
                raise ValueError(f"Found NULL value in line: {args}")

        h = str(args)
        if h in self.cache:
            return
        self.cache[h] = True

        self.writer.writerow(args)

    @staticmethod
    def cypher_exec(cypher: str) -> Any:
        graph = neo4j.get_instance()
        return graph.cypher(cypher)

    @staticmethod
    def get_properties(fields: List[str]) -> str:
        properties: List[str] = []

        for f in fields:
            tokens = f.split(":")
            if tokens[1] == "string":
                properties.append(f"{tokens[0]}: line.{tokens[0]}")
            elif tokens[1] == "int":
                properties.append(f"{tokens[0]}: toInteger(line.{tokens[0]})")
            elif tokens[1] == "float":
                properties.append(f"{tokens[0]}: toFloat(line.{tokens[0]})")

        return ",".join(properties)

    @classmethod
    def switch_label(cls, old_label: str, new_label: str, limit: int = 10000) -> None:
        cypher = f"""
            MATCH (n:{old_label})
            WITH n
            LIMIT {limit}
            SET n:{new_label}
            REMOVE n:{old_label}
            RETURN count(n)
        """
        result = cls.cypher_exec(cypher)

        num = result[0][0]
        log.info("{} {} > {}", num, old_label, new_label)
        if num > 0:
            cls.switch_label(old_label, new_label, limit=limit)

    @classmethod
    def delete_nodes(cls, label: str, limit: int = 10000) -> None:
        cypher = f"""
            MATCH (n:{label})
            WITH n
            LIMIT {limit}
            DETACH DELETE n
            RETURN count(n)
        """

        result = cls.cypher_exec(cypher)

        num = result[0][0]
        log.info("Deleted {} {} nodes", num, label)
        if num == limit:
            cls.delete_nodes(label, limit=limit)

    @classmethod
    def delete_relationships(
        cls, label1: str, relation: str, label2: str, limit: int = 50000
    ) -> None:
        cypher = f"""
            MATCH (:{label1})-[r:{relation}]->(:{label2})
            WITH r
            LIMIT {limit}
            DELETE r
            RETURN count(r)
        """

        result = cls.cypher_exec(cypher)

        num = result[0][0]
        log.info(
            "Deleted {} (:{}-[{}]->(:{}) relationships", num, label1, relation, label2
        )
        if num == limit:
            cls.delete_relationships(label1, relation, label2, limit=limit)

    def close(self) -> None:
        if self.handle:
            self.handle.close()

    def __del__(self) -> None:
        self.close()


class NodeDump(DataDump):
    def __init__(self, label: str, fields: List[str]) -> None:

        filename = f"{label}.tsv".lower()
        super().__init__(filename, fields)
        self.label = label

    # def bulk_delete(self, limit: int = 10000) -> None:
    #     self.delete_nodes(self.label, limit=limit)

    def dump(self, *args: Any) -> None:
        if len(args) != len(self.fields):
            raise ValueError(
                f"Unexpected number of fields\nReceived {len(args)} ({args})\n"
                f"Expected {len(self.fields)} ({self.fields})"
            )
        self.print_line(args)

    def store(self, chunk_size: int = 10000) -> None:

        self.close()

        log.info("Storing {} ({}) nodes", self.count, self.label)

        properties: str = self.get_properties(self.fields)

        cypher = f"""
USING PERIODIC COMMIT {chunk_size}
LOAD CSV WITH HEADERS
FROM 'file:///{self.filename}'
AS line
FIELDTERMINATOR '\t'

MERGE (:{self.label} {{
    {properties}
}})"""

        self.cypher_exec(cypher)


class RelationDump(DataDump):

    NODE1_LABEL = "node1"
    NODE2_LABEL = "node2"

    def __init__(
        self,
        label1: str,
        relation: str,
        label2: str,
        fields: List[str],
        ignore_indexes: bool = False,
    ) -> None:

        filename = f"{label1}_{relation}_{label2}.tsv".lower()
        # This is to prevent duplicates in node keys
        self.key1 = fields[0]
        self.key2 = fields[1]
        fields[0] = f"{self.NODE1_LABEL}:string"
        fields[1] = f"{self.NODE2_LABEL}:string"
        super().__init__(filename, fields)

        self.label1 = label1
        self.relation = relation
        self.label2 = label2

        if not ignore_indexes:
            self.verify_indexes(self.label1, self.key1)
            self.verify_indexes(self.label2, self.key2)

    # def bulk_delete(self, limit: int = 10000) -> None:
    #     self.delete_relationships(
    #         self.label1, self.relation, self.label2, limit=limit
    #     )

    def dump(self, *args: Any) -> None:
        if len(args) != len(self.fields):
            raise ValueError(
                f"Unexpected number of fields\nReceived {len(args)} ({args})\n"
                f"Expected {len(self.fields)} ({self.fields})"
            )
        self.print_line(args)

    def store(self, chunk_size: int = 10000) -> None:

        self.close()

        log.info(
            "Storing {} ({})-[:{}]->({}) relationships",
            self.count,
            self.label1,
            self.relation,
            self.label2,
        )

        field1 = self.fields[0].split(":")[0]
        field2 = self.fields[1].split(":")[0]

        properties: str = self.get_properties(self.fields[2:])

        cypher = f"""
USING PERIODIC COMMIT {chunk_size}
LOAD CSV WITH HEADERS
FROM 'file:///{self.filename}'
AS line
FIELDTERMINATOR '\t'

MATCH (node1: {self.label1} {{{self.key1}: line.{field1}}})
MATCH (node2: {self.label2} {{{self.key2}: line.{field2}}})
MERGE (node1)-[:{self.relation} {{{properties}}}]->(node2)
"""

        self.cypher_exec(cypher)

    @staticmethod
    def verify_indexes(label: str, key: str) -> None:
        graph = neo4j.get_instance()
        indexes = graph.cypher("CALL db.indexes()")
        for index in indexes:
            labelsOrTypes = index[7]
            properties = index[8]

            if len(labelsOrTypes) == 1 and len(properties) == 1:
                if labelsOrTypes[0] == label and properties[0] == key:
                    log.debug("Found an index for {}.{}", label, key)
                    break
        else:
            raise ValueError(
                f"Can't find an index for {label}.{key}: "
                "add an index or skip this check with ignore_indexes=True"
            )
