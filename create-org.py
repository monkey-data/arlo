import sys

from arlo_server import create_organization

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python create-org.py <org_name>")
        sys.exit(1)

    print(create_organization(sys.argv[1]).id)