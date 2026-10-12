from colorama import Fore, Style

from cloudsneeker.brand import brand  # cloudsneeker-hook
from prowler.config.config import banner_color, orange_color, prowler_version, timestamp

PRODUCT_NAME = brand.name  # cloudsneeker-hook


def print_banner(legend: bool = False, provider: str = None):
    """
    Prints the banner with optional legend for color codes.

    Parameters:
    - legend (bool): Flag to indicate whether to print the color legend or not. Default is False.
    - provider (str): The provider being scanned, used to tailor the Prowler Cloud banner.

    Returns:
    - None
    """
    banner = rf"""{banner_color}{PRODUCT_NAME} CLI - v{prowler_version}{Style.RESET_ALL}
{Fore.YELLOW}Date: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}
"""
    print(banner)

    print_prowler_cloud_banner(provider)

    if legend:
        print(f"""
{Style.BRIGHT}Color code for results:{Style.RESET_ALL}
- {Fore.YELLOW}MANUAL (Manual check){Style.RESET_ALL}
- {Fore.GREEN}PASS (Recommended value){Style.RESET_ALL}
- {orange_color}MUTED (Muted by muted list){Style.RESET_ALL}
- {Fore.RED}FAIL (Fix required){Style.RESET_ALL}
            """)


def print_prowler_cloud_banner(provider: str = None):
    """Kept so existing CLI call sites stay valid. Cloudsneeker does not advertise another product."""
    return
