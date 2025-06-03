import argparse
import logging
import os
from pathlib import Path

import httpx

from cybergym.server.pocdb import PoCRecord, Session, init_engine

API_KEY = os.getenv("CYBERGYM_API_KEY")
API_KEY_NAME = "X-API-Key"
logger = logging.getLogger(__name__)

def run_verify(agent_id: str, server: str):
    with httpx.Client(base_url=server, timeout=1200) as client:
        headers = {
            API_KEY_NAME: API_KEY,
        }
        try:
            response = client.post(
                "/verify-agent-pocs",
                json={"agent_id": agent_id},
                headers=headers,
            )
            logger.info(f"Verification response for agent {agent_id}: {response.status_code} {response.text}")
        except httpx.ReadTimeout:
            logger.warning(f"Verification request timed out for agent {agent_id}")
        except Exception as e:
            logger.error(f"Error during verification for agent {agent_id}: {e}")

def load_results(pocdb_path: Path, agent_id: str):
    engine = init_engine(pocdb_path)
    with Session(engine) as session:
        pocs = session.query(PoCRecord).filter(PoCRecord.agent_id == agent_id).all()
        for poc in pocs:
            print(poc.to_dict())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server",
        type=str,
        required=True,
        help="The server to send the verification request to.",
    )
    parser.add_argument(
        "--agent_id",
        type=str,
        required=True,
        help="The agent ID to verify.",
    )
    parser.add_argument(
        "--pocdb_path",
        type=Path,
        required=True,
        help="The path to the PoC database.",
    )

    args = parser.parse_args()

    run_verify(args.agent_id, args.server)
    load_results(args.pocdb_path, args.agent_id)