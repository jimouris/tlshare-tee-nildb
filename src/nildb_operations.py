"""Schema Create example using the SecretVault wrapper"""
"""Data Create and Read example using the SecretVault wrapper"""

import asyncio
import json
import sys
import os
from secretvaults import SecretVaultWrapper, OperationType
from org_config import org_config

SCHEMA_ID = os.getenv("SCHEMA_ID")
QUERY_ID = os.getenv("QUERY_ID")

async def create_schema() -> str:
    """
    Main function to initialize the SecretVaultWrapper and create a new schema.
    """
    try:
        # Load the schema from schema_match.json
        with open("src/amazon_schema.json", "r", encoding="utf8") as schema_file:
            schema = json.load(schema_file)


        # Initialize the SecretVaultWrapper instance with the org configuration
        org = SecretVaultWrapper(org_config["nodes"], org_config["org_credentials"])
        await org.init()

        # Create a new schema
        new_schema = await org.create_schema(schema, "Verifiable Amazon Purchases")
        print("📚 New Schema:", new_schema)
        print("Store schema in the .env file as SCHEMA_ID.")
        return new_schema
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)

async def upload_amazon_purchase(purchase: int) -> list[str]:
    """
    Main function to write to nodes using the SecretVaultWrapper.
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

        # Write data to nodes
        data = [
            {
                "purchase": {"%allot": purchase}
            }
        ]
        data_written = await collection.write_to_nodes(data)
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

async def create_sum_query() -> str:
    """
    Main function to initialize the SecretVaultWrapper and create a new schema.
    """
    try:
        with open("src/amazon_schema_query_sum.json", "r", encoding="utf8") as query_file:
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

async def execute_sum_query():
    """
    Main function to initialize the SecretVaultWrapper and execute a query.
    """
    try:
        # Initialize the SecretVaultWrapper instance with the org configuration
        org = SecretVaultWrapper(
            org_config["nodes"],
            org_config["org_credentials"],
            operation=OperationType.SUM,  # we'll be doing a sum operation on encrypted values
        )
        await org.init()

        # Define the query payload
        query_payload = {
            "id": QUERY_ID,
            "variables": {},
        }

        # Execute the query
        query_result = await org.query_execute_on_nodes(query_payload)
        # Even though years_in_web3 entries are encrypted, we can get the sum without individually decrypting them
        print("📚 Query Result:", json.dumps(query_result, indent=2))
    except RuntimeError as error:
        print(f"❌ Failed to use SecretVaultWrapper: {str(error)}")
        sys.exit(1)


# Run the async main function
if __name__ == "__main__":
    SCHEMA_ID = asyncio.run(create_schema())
    QUERY_ID = asyncio.run(create_sum_query())
    # asyncio.run(execute_sum_query())
    sys.exit(0)
