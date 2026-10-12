from fastmcp.utilities.logging import get_logger

from prowler_mcp_server.cloudsneeker.brand import brand  # cloudsneeker-hook

# Create and export logger
logger = get_logger(brand.server_name)  # cloudsneeker-hook
