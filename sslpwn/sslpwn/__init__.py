"""sslpwn; Automated testing of BEAST, Lucky13, BREACH, POODLE, CRIME, Heartbleed, Ticketbleed, Renegotiation, Freak, Logjam and ROBOT vulnerabilities."""
import urllib3

__version__ = "2.0.0"

# Suppress insecure HTTPS request warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
