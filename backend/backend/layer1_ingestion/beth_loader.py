# backend/layer1_ingestion/beth_loader.py
"""
Bulk-loads the BETH dataset CSV/parquet into the provenance graph.
Run once offline to pre-populate the graph before inference.
"""
import csv
import os
from typing import Generator
from layer1_ingestion.log_parser import parse_beth_row
from layer1_ingestion.graph_builder import provenance_graph


BETH_CSV_PATH = os.getenv("BETH_CSV", "./data/beth_dataset.csv")


def stream_beth(path: str = BETH_CSV_PATH, limit: int = 50_000) -> Generator:
    """Stream BETH rows as dicts without loading all 8M into RAM."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            yield row


def load_beth_into_graph(path: str = BETH_CSV_PATH, limit: int = 50_000) -> int:
    """
    Parse BETH rows and insert into provenance graph.
    Returns number of events successfully ingested.
    """
    count = 0
    for row in stream_beth(path, limit):
        event = parse_beth_row(row)
        if event:
            provenance_graph.add_event(event)
            count += 1
    print(f"[BethLoader] Ingested {count} events → graph has "
          f"{provenance_graph.node_count()} nodes, {provenance_graph.edge_count()} edges")
    return count


if __name__ == "__main__":
    load_beth_into_graph()
