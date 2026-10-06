import os
from dotenv import load_dotenv
from pymetasploit3.msfrpc import MsfRpcClient

load_dotenv()

host = os.getenv('MSF_RPC_HOST')
port = int(os.getenv('MSF_RPC_PORT'))
user = os.getenv('MSF_RPC_USER')
password = os.getenv('MSF_RPC_PASS')
ssl = os.getenv('MSF_RPC_SSL', 'true').lower() == 'true'

client = MsfRpcClient(password, server=host, port=port, ssl=ssl)
print(client.core.version)
