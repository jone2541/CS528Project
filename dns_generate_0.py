#!/usr/bin/env python3
#chmod 755 project.py
#sudo ./dns_generate_0.py
import socket
import time
import random
import argparse
import sys
import signal # To handle Ctrl+C gracefully

# --- Configuration ---
# List of common, legitimate domains to query.
DEFAULT_DOMAINS = [
    "www.cs.purdue.edu", "cs.purdue.edu",
    "www.purdue.edu", "purdue.edu",
    "www.google.com", "google.com",
    "www.youtube.com", "youtube.com",
    "www.facebook.com", "facebook.com",
    "www.wikipedia.org", "wikipedia.org",
    "www.amazon.com", "amazon.com",
    "www.reddit.com", "reddit.com",
    "www.twitter.com", "twitter.com", # or x.com
    "x.com",
    "www.instagram.com", "instagram.com",
    "www.linkedin.com", "linkedin.com",
    "www.microsoft.com", "microsoft.com",
    "update.microsoft.com",
    "www.apple.com", "apple.com",
    "swscan.apple.com", "gs.apple.com",
    "github.com", "raw.githubusercontent.com",
    "pypi.org",
    "pool.ntp.org", # Network Time Protocol servers often queried
    "www.google-analytics.com",
    "doubleclick.net", # Common ad network domains
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "time.google.com",
    "time.apple.com",
    "time.windows.com",
    "ctldl.windowsupdate.com", # Windows update related
    "clientservices.googleapis.com", # Android connectivity checks often use this
    "connectivitycheck.gstatic.com", # Google connectivity
    "detectportal.firefox.com", # Firefox connectivity
    "www.yahoo.com",
    "www.bing.com",
    "www.duckduckgo.com",
    "www.bbc.com", "news.bbc.co.uk",
    "www.cnn.com",
    "www.nytimes.com",
    "weather.com",
    # Add local/regional popular sites if desired
]

DEFAULT_DELAY_MEAN = 1.0  # Average seconds between queries
DEFAULT_DELAY_STDDEV = 0.5 # Standard deviation for delay randomization
MIN_DELAY = 0.1         # Minimum delay to prevent excessive speed

# --- Global flag for graceful shutdown ---
running = True

def signal_handler(sig, frame):
    """Handles Ctrl+C"""
    global running
    print("\nCtrl+C detected. Stopping generation...")
    running = False

def resolve_domain(domain):
    """
    Performs a DNS lookup for the given domain using the system's resolver.
    Returns True on success, False on failure.
    """
    global running
    if not running: # Check flag before proceeding
        return False
    try:
        # socket.getaddrinfo is preferred as it handles IPv4/IPv6 and uses system defaults
        # We don't strictly need the result, just the act of resolving
        results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP) # Specify TCP to avoid potential issues? Or leave 0? Let's use default (0)
        # results = socket.getaddrinfo(domain, None) # Simpler, often sufficient
        
        # Optionally pick a result to print
        first_result = random.choice(results)
        family, socktype, proto, canonname, sockaddr = first_result
        ip_address = sockaddr[0] # Get the IP address from the sockaddr tuple
        print(f"{time.strftime('%H:%M:%S')} - Resolved {domain} -> {ip_address}")
        return True
    except socket.gaierror as e:
        # Common error if domain doesn't exist or network issue
        print(f"{time.strftime('%H:%M:%S')} - Failed to resolve {domain}: {e}")
        return False
    except Exception as e:
        # Catch other potential errors
        print(f"{time.strftime('%H:%M:%S')} - Unexpected error resolving {domain}: {e}")
        return False

def main():
    """Main function to parse arguments and run the generation loop."""
    global running
    parser = argparse.ArgumentParser(description="Generate normal DNS lookup traffic by resolving common domain names.")

    parser.add_argument(
        "-d", "--delay", type=float, default=DEFAULT_DELAY_MEAN,
        help=f"Average delay (in seconds) between DNS queries (default: {DEFAULT_DELAY_MEAN})"
    )
    parser.add_argument(
        "--delay-stddev", type=float, default=DEFAULT_DELAY_STDDEV,
        help=f"Standard deviation for delay randomization (default: {DEFAULT_DELAY_STDDEV})"
    )
    parser.add_argument(
        "-n", "--num-queries", type=int, default=0,
        help="Number of queries to perform (default: 0, runs indefinitely until Ctrl+C)"
    )
    parser.add_argument(
        "--domains-file", type=str, default=None,
        help="Path to a file containing domain names (one per line) to use instead of the default list."
    )

    args = parser.parse_args()

    # --- Load Domains ---
    domains_to_query = DEFAULT_DOMAINS
    if args.domains_file:
        try:
            with open(args.domains_file, 'r') as f:
                domains_to_query = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not domains_to_query:
                print(f"Error: Domain file '{args.domains_file}' is empty or only contains comments.")
                sys.exit(1)
            print(f"Loaded {len(domains_to_query)} domains from {args.domains_file}")
        except FileNotFoundError:
            print(f"Error: Domain file not found: {args.domains_file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading domain file '{args.domains_file}': {e}")
            sys.exit(1)

    # --- Setup Signal Handler ---
    signal.signal(signal.SIGINT, signal_handler) # Handle Ctrl+C

    # --- Generation Loop ---
    print("--- Starting Normal DNS Traffic Generation ---")
    print(f"Querying domains from {'default list' if not args.domains_file else args.domains_file}.")
    print(f"Average delay: {args.delay}s (+/- stddev {args.delay_stddev}s)")
    if args.num_queries > 0:
        print(f"Will perform {args.num_queries} queries.")
    else:
        print("Running indefinitely. Press Ctrl+C to stop.")
    print("-" * 40)

    query_count = 0
    while running and (args.num_queries == 0 or query_count < args.num_queries):
        try:
            # Select a random domain
            domain = random.choice(domains_to_query)

            # Perform the DNS resolution
            resolve_domain(domain)
            query_count += 1

            # Wait for a random delay (Gaussian distribution around the mean)
            # Ensure delay is not negative and respects the minimum
            sleep_time = max(MIN_DELAY, random.gauss(args.delay, args.delay_stddev))
            # print(f"Sleeping for {sleep_time:.2f} seconds...") # Uncomment for debugging delay
            time.sleep(sleep_time)

        except Exception as e:
            print(f"Error in main loop: {e}. Continuing...")
            time.sleep(1) # Brief pause after unexpected error

    print("-" * 40)
    print(f"--- Normal DNS Traffic Generation Stopped ---")
    print(f"Performed {query_count} DNS lookups.")

if __name__ == "__main__":
    main()