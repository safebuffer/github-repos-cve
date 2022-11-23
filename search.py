from github import Github
import re
import sys
import time,random
import argparse
from enum import Enum



CVE_RE1 = r'CVE[-|_]\d{4}[-|_]\d{4,7}'

GitHubAPI = None
GitRepo = None

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    Black        = "\033[30m"
    Red          = "\033[31m"
    Green        = "\033[32m"
    Yellow       = "\033[33m"
    Blue         = "\033[34m"
    Magenta      = "\033[35m"
    Cyan         = "\033[36m"
    LightGray    = "\033[37m"
    DarkGray     = "\033[90m"
    LightRed     = "\033[91m"
    LightGreen   = "\033[92m"
    LightYellow  = "\033[93m"
    LightBlue    = "\033[94m"
    LightMagenta = "\033[95m"
    LightCyan    = "\033[96m"

    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_red(text):
    print(bcolors.FAIL + str(text) + bcolors.ENDC)

def print_green(text):
    print(bcolors.OKGREEN + str(text) + bcolors.ENDC)

def print_blue(text):
    print(bcolors.Blue + str(text) + bcolors.ENDC)


def jitter():
    time.sleep(random.randint(1,3))

class FindingType(Enum):
    CODE = "code"
    COMMIT = "commit"
    ISSUE = "issue"


global_findgs = []
GitRepo = None
MAIN_QUERY = None


def main_search(options):
    global global_findgs

    if options.code or options.all:
        # search code comments  
        print_blue(f"[*] Searching code {options.target}")
        req = GitHubAPI.search_code(MAIN_QUERY)
        for i in req:
            jitter()
            try:
                contentreq = GitRepo.get_contents(path=i.path)
                content = contentreq.decoded_content
                cves = re.findall(CVE_RE1, content.decode('utf-8'))
                for cve in cves:
                    cve = cve.replace('_','-')
                    obj = {
                        "url":f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
                        "cve":cve,
                        "type":FindingType.CODE.value
                    }
                    global_findgs.append(obj) if obj not in global_findgs else False
                    print_green(f"[+] Found {cve} at {i.path}")
            except Exception as e:
                print_red(f"[-] error {e}")

    if options.commits or options.all:
        # # search commits messages
        print_blue(f"[*] Searching commits {options.target}")
        req = GitHubAPI.search_commits(MAIN_QUERY)
        for i in req:
            jitter()
            commit = i.commit
            try:
                cves = re.findall(CVE_RE1, commit.message)
                
                for cve in cves:
                    cve = cve.replace('_','-')

                    print_green(f"[+] Found {cve} at {i.sha} commit message")
                    obj = {
                        "url":f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
                        "cve":cve,
                        "type":FindingType.COMMIT.value
                    }
                    global_findgs.append(obj) if obj not in global_findgs else False

            except Exception as e:
                print_red(f"[-] error {e}")

    if options.issues or options.all:
        # search issues messages
        print_blue(f"[*] Searching issues {options.target}")
        req = GitHubAPI.search_issues(MAIN_QUERY)
        for i in req:
            jitter()
            try:
                cves = re.findall(CVE_RE1, str(i.raw_data))
                for cve in cves:              
                    cve = cve.replace('_','-')
    
                    obj = {
                        "url":f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
                        "cve":cve,
                        "type":FindingType.COMMIT.value
                    }
                    global_findgs.append(obj) if obj not in global_findgs else False

                    print_green(f"[+] Found {cve} at {i.url} issue")
            except Exception as e:
                print_red(f"[-] error {e}")


def main():
    global GitHubAPI,MAIN_QUERY,GitRepo

    description = """
        Search CVE's in github repo for quick wins
    """
    parser = argparse.ArgumentParser(usage=f"{sys.argv[0]}", add_help = True, description = description)

    performance = parser.add_argument_group('Search Options')
    performance.add_argument('-issues', action='store_true', help='Search issues',default=False)
    performance.add_argument('-commits', action='store_true', help='Search commits',default=False)
    performance.add_argument('-code', action='store_true', help='Search code',default=False)
    performance.add_argument('-all', action='store_true', help='Search All',default=False)

    target = parser.add_argument_group('Target Options')
    target.add_argument('-target', action='store', help='target repo in this format org/repo ',type=str,required=True)
    target.add_argument('-token', action='store', help='Github Token',type=str,required=True)

    options = parser.parse_args()

    if not any([options.issues,options.issues,options.code,options.all]):
        options.all = True
        print_blue("[*] Searching Everything ")

    try:
        GitHubAPI = Github(options.token,timeout=120,per_page=100,retry=5)
    except Exception as e:
        print_red("[-] can't connect to github")
        raise e
        
    repo = str(options.target)
    try:
        GitRepo = GitHubAPI.get_repo(repo)
    except Exception as e:
        print_red(f"[-] can't find the repo {e} {repo}")
        exit()
    
    MAIN_QUERY = f"repo:{repo} CVE"
    main_search(options)

if __name__ == "__main__":
    main()

