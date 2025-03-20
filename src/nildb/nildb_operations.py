"""Schema Create, upload data and execute query example using the SecretVault wrapper"""

import argparse
import asyncio
import json
import os
import sys
import uuid

import nilql
from secretvaults import OperationType, SecretVaultWrapper

from src.nildb.org_config import org_config

SCHEMA_ID = os.getenv("SCHEMA_ID")
QUERY_ID = os.getenv("QUERY_ID")

# Initialize encryption keys
NUM_NODES = len(org_config["nodes"])
SUM_KEY = nilql.ClusterKey.generate({"nodes": [{}] * NUM_NODES}, {"sum": True})
STORE_KEY = nilql.ClusterKey.generate({"nodes": [{}] * NUM_NODES}, {"store": True})


async def create_schema() -> str:
    """
    Main function to initialize the SecretVaultWrapper and create a new schema.
    """
    try:
        # Load the schema from schema_match.json
        with open("src/nildb/schemas/schema.json", "r", encoding="utf8") as schema_file:
            schema = json.load(schema_file)

        # Initialize the SecretVaultWrapper instance with the org configuration
        org = SecretVaultWrapper(org_config["nodes"], org_config["org_credentials"])
        await org.init()

        # Create a new schema
        new_schema = await org.create_schema(
            schema, "Secret Shared Data With Provenance"
        )
        print("📚 New Schema:", new_schema)
        print("Store schema in the .env file as SCHEMA_ID.")
        return new_schema
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


async def upload_to_nildb(data: str | int, origin: str) -> list[str]:
    """
    Upload data to nilDB with proper type handling and origin description.

    Args:
        data: The data to upload (string or integer)
        origin: The origin of the data (e.g., "amazon", "tiktok")

    Returns:
        List of created record IDs
    """
    try:
        # Initialize the SecretVaultWrapper instance with the org configuration and schema ID
        collection = SecretVaultWrapper(
            org_config["nodes"],
            org_config["org_credentials"],
            SCHEMA_ID,
        )
        await collection.init()
        _id = str(uuid.uuid4())

        # Prepare data based on type
        if isinstance(data, int):
            encrypted_data = nilql.encrypt(SUM_KEY, data)
            nildb_data = [
                {"number": {"%share": share}, "description": origin, "_id": _id}
                for share in encrypted_data
            ]
        else:
            encrypted_number = nilql.encrypt(SUM_KEY, 0)
            encrypted_string = nilql.encrypt(STORE_KEY, str(data))
            nildb_data = [
                {
                    "number": {"%share": num_share},
                    "string": {"%share": str_share},
                    "description": origin,
                    "_id": _id,
                }
                for num_share, str_share in zip(encrypted_number, encrypted_string)
            ]
        print(f"🔑 Encrypted data: {nildb_data}")

        # Write data to nodes
        data_written = await collection.write_to_nodes([nildb_data], allot_data=False)

        # Extract unique created IDs from the results
        new_ids = list(
            {
                created_id
                for item in data_written
                if item.get("result")
                for created_id in item["result"]["data"]["created"]
            }
        )
        return new_ids
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


async def download_from_nildb(origin: str = None) -> list[dict]:
    """
    Download and decrypt data from nilDB.

    Args:
        record_ids: List of record IDs to download

    Returns:
        List of decrypted data records
    """
    try:
        # Initialize the SecretVaultWrapper instance with the org configuration and schema ID
        collection = SecretVaultWrapper(
            org_config["nodes"],
            org_config["org_credentials"],
            SCHEMA_ID,
            operation=OperationType.SUM,
        )
        await collection.init()

        # Read data from nodes
        data_read = await collection.read_from_nodes(
            {"description": origin} if origin else {}, unify_data=False
        )

        # Reconstruct and decrypt the data
        decrypted_data = []
        for record in data_read:
            if record.get("shares"):
                # Extract shares from the result
                shares = record["shares"]

                # Separate number and string shares
                number_shares = [s["number"]["%share"] for s in shares]
                string_shares = [
                    s.get("string", {}).get("%share", None) for s in shares
                ]

                # Decrypt the data
                if all(s is None for s in string_shares):
                    # Number data
                    decrypted_data.append(
                        {
                            "number": nilql.decrypt(SUM_KEY, number_shares),
                            "description": shares[0]["description"],
                            "_id": shares[0]["_id"],
                        }
                    )
                else:
                    # String data
                    decrypted_data.append(
                        {
                            "number": nilql.decrypt(SUM_KEY, number_shares),
                            "string": nilql.decrypt(STORE_KEY, string_shares),
                            "description": shares[0]["description"],
                            "_id": shares[0]["_id"],
                        }
                    )
        print(
            f"📚 Query Result for{' all' if origin is None else f' {origin}'} data:",
            json.dumps(decrypted_data, indent=2),
        )

    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


async def create_sum_query() -> str:
    """
    Main function to initialize the SecretVaultWrapper and create a new schema.
    """
    try:
        with open(
            "src/nildb/schemas/query_sum.json", "r", encoding="utf8"
        ) as query_file:
            query = json.load(query_file)

        # Initialize the SecretVaultWrapper instance with the org configuration
        org = SecretVaultWrapper(org_config["nodes"], org_config["org_credentials"])
        await org.init()

        # Create a new schema
        new_query = await org.create_query(
            query,
            SCHEMA_ID,
            "Returns sum of purchases and count of users",
        )
        print("📚 New Query:", new_query)
        print("Store query in the .env file as QUERY_ID.")
        return new_query
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


async def execute_sum_query(origin: str = "*"):
    """
    Execute a query to sum values, filtered by origin.

    Args:
        origin: Origin to filter by (e.g., 'amazon', 'tiktok', '*' for all)
    """
    try:
        # Initialize the SecretVaultWrapper instance with the org configuration
        org = SecretVaultWrapper(
            org_config["nodes"],
            org_config["org_credentials"],
            operation=OperationType.SUM,
        )
        await org.init()

        # Define the query payload - always include origin
        query_payload = {"id": QUERY_ID, "variables": {"origin": origin}}

        # Execute the query
        query_result = await org.query_execute_on_nodes(query_payload)
        print(
            f"📚 Query Result for{' all' if origin == '*' else f' {origin}'} data:",
            json.dumps(query_result, indent=2),
        )
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="nilDB operations: create schema and query, execute sum query"
    )

    # Operation flags
    parser.add_argument(
        "--create", action="store_true", help="Create schema and query in nilDB"
    )
    parser.add_argument(
        "--query",
        metavar="ORIGIN",
        nargs="?",
        const="*",
        help="Download raw data, optionally filtered by origin (e.g., 'amazon', 'tiktok', '*' for all)",
    )
    parser.add_argument(
        "--query-sum",
        metavar="ORIGIN",
        nargs="?",
        const="*",
        help="Execute sum query, optionally filtered by origin (e.g., 'amazon', 'tiktok', '*' for all)",
    )

    return parser.parse_args()


# Run the async main function
if __name__ == "__main__":
    args = parse_args()

    if not (args.create or args.query or args.query_sum is not None):
        print(
            "Please specify an operation (--create or --query or --query-sum). Use -h for help."
        )
        sys.exit(1)

    if args.create:
        print("\nCreating new schema...")
        SCHEMA_ID = asyncio.run(create_schema())
        print(f"Schema created! Don't forget to update {SCHEMA_ID} in your .env file!")

        print("\nCreating new sum query...")
        QUERY_ID = asyncio.run(create_sum_query())
        print(f"Query created! Don't forget to update {QUERY_ID} in your .env file!")

    if args.query is not None:
        print(f"\nDownloading raw data for {args.query}...")
        asyncio.run(download_from_nildb(args.query))

    if args.query_sum is not None:
        if not QUERY_ID:
            print("❌ Error: QUERY_ID not found in environment variables")
            print("Please set QUERY_ID in your .env file")
            sys.exit(1)
        print(f"\nExecuting sum query for {args.query_sum}...")
        asyncio.run(execute_sum_query(args.query_sum))

    sys.exit(0)
