import os
import platform
import subprocess
import sys
import requests
from typing import Mapping

import boto3
from dify_plugin import Endpoint
from werkzeug import Request, Response


class DifyPluginSecurityCheckEndpoint(Endpoint):
    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        def generator():
            yield "<html lang='en'>"
            yield "<head>"
            yield "<meta charset='UTF-8'>"
            yield "<meta http-equiv='X-UA-Compatible' content='IE=edge'>"
            yield "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            yield "<title>Security check</title>"
            yield "</head>"

            yield "<body>"
            yield "<h1>Security check</h1>"

            # Check environment
            yield "<h2>Environment</h2>"
            yield "<p style='color: darkgray'>Checking environment...</p>"

            yield "<h3>Hardware info</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"

            yield "<h4>CPU info</h4>"
            try:
                cpu_info = subprocess.check_output(["lscpu"])
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{cpu_info.decode()}"
                yield "</div>"
            except Exception:
                cpu_info = None

            if cpu_info is None:
                try:
                    cpu_info = subprocess.check_output(["cat", "/proc/cpuinfo"])
                    yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                    yield f"{cpu_info.decode()}"
                    yield "</div>"
                except Exception:
                    yield "<p style='color: red'>Error getting CPU info</p>"

            yield "<h4>Memory info</h4>"
            try:
                mem_info = subprocess.check_output(["cat", "/proc/meminfo"])
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{mem_info.decode()}"
                yield "</div>"
            except Exception:
                yield "<p style='color: red'>Error getting memory info</p>"

            yield "<h4>Disk info</h4>"
            try:
                disk_info = subprocess.check_output(["df", "-h"])
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{disk_info.decode()}"
                yield "</div>"
            except Exception:
                yield "<p style='color: red'>Error getting disk info</p>"

            yield "<h4>Network info</h4>"
            try:
                network_info = subprocess.check_output(["ip", "a"])
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{network_info.decode()}"
                yield "</div>"
            except Exception:
                network_info = None

            if network_info is None:
                try:
                    network_info = subprocess.check_output(["ifconfig"])
                    yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                    yield f"{network_info.decode()}"
                    yield "</div>"
                except Exception:
                    network_info = None

            if network_info is None:
                try:
                    sys_class_net = subprocess.check_output(["ls /sys/class/net"], shell=True, text=True)
                    sys_class_net_array = sys_class_net.split("\n")
                    yield "<p style='color: darkgray'>Checking network interfaces...</p>"
                    for interface in sys_class_net_array:
                        yield f"<p style='color: darkgray'>Checking interface {interface}...</p>"
                        address = subprocess.check_output(["cat", f"/sys/class/net/{interface}/address"])
                        yield f"Interface: {interface} <br>"
                        yield f" -> MAC address: {address.decode()} <br>"
                except Exception:
                    yield "<p style='color: red'>Error getting network info</p>"

            yield "</div>"

            yield "<h3>Platform info</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            yield f"Platform: {platform.platform()} <br>"
            yield f"System: {platform.system()} <br>"
            yield f"Node: {platform.node()} <br>"
            yield f"Release: {platform.release()} <br>"
            yield f"Version: {platform.version()} <br>"
            yield f"Machine: {platform.machine()} <br>"
            yield "</div>"

            yield "<h3>Python info</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            yield f"Python version: {sys.version} <br>"
            yield f"Python path: {sys.path} <br>"
            yield f"Python executable: {sys.executable} <br>"
            yield "</div>"

            yield "<h3>Environment variables</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            for key, value in os.environ.items():
                yield f"{key}: {value} <br>"
            yield "</div>"

            # User info
            yield "<h3>User info</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            try:
                getlogin = os.getlogin()
                yield f"Get login: {getlogin} <br>"
            except Exception:
                pass
            try:
                getuid = os.getuid()
                yield f"Get UID: {getuid} <br>"
            except Exception:
                pass
            try:
                getgid = os.getgid()
                yield f"Get GID: {getgid} <br>"
            except Exception:
                pass
            try:
                groups = os.getgroups()
                yield f"Groups: {groups} <br>"
            except Exception:
                pass
            try:
                whoami = subprocess.check_output(["whoami"])
                yield f"Whoami: {whoami.decode()} <br>"
            except Exception:
                pass
            try:
                id = subprocess.check_output(["id"])
                yield f"ID: {id.decode()} <br>"
            except Exception:
                pass
            yield "</div>"

            # Sudo info
            yield "<h3>Sudo info</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            try:
                sudo = subprocess.check_output(["sudo", "id"])
                yield f"Sudo ID: {sudo.decode()} <br>"
            except Exception:
                yield "<p style='color: red'>Error getting sudo info</p>"
            yield "</div>"

            # /etc/passwd
            yield "<h3>/etc/passwd</h3>"
            try:
                with open("/etc/passwd", "r") as f:
                    passwd = f.read()
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                passwd = None

            if passwd is not None:
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{passwd}"
                yield "</div>"
            else:
                yield "<p style='color: red'>Error getting /etc/passwd</p>"

            # Check App
            yield "<h2>App</h2>"
            # Check current directory
            yield "<p style='color: darkgray'>Checking current directory...</p>"
            try:
                results = []
                for root, _dirs, files in os.walk("."):
                    for file in files:
                        results.append(os.path.join(root, file))
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                results = None

            if results is not None:
                yield "<h3>Current directory files</h3>"
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                for file in results:
                    yield f"{file} <br>"
                yield "</div>"
            else:
                yield "<p style='color: red'>No files found</p>"

            # Check app Dockerfile
            yield "<p style='color: darkgray'>Checking Dockerfile...</p>"
            try:
                with open("Dockerfile", "r") as f:
                    dockerfile = f.read()
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                dockerfile = None

            if dockerfile is not None:
                yield "<h3>Dockerfile</h3>"
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px; white-space: pre-wrap'>"
                yield f"{dockerfile}"
                yield "</div>"

            # Invoke params
            yield "<h3>Invoke params</h3>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            yield f"Request remote_addr: {r.remote_addr} <br>"
            yield f"Request remote_user: {r.remote_user} <br>"
            yield f"Request scheme: {r.scheme} <br>"
            yield f"Request full_path: {r.full_path} <br>"
            yield f"Request host: {r.host} <br>"
            yield f"Request host_url: {r.host_url} <br>"
            yield f"Request path: {r.path} <br>"
            yield f"Request method: {r.method} <br>"
            yield f"Request content_length: {r.content_length} <br>"
            yield f"Request content_type: {r.content_type} <br>"
            yield f"Request data: {r.data} <br>"
            yield f"Request form: {r.form} <br>"
            yield f"Request args: {r.args} <br>"
            yield f"Request values: {r.values} <br>"
            yield f"Request files: {r.files} <br>"
            yield f"Request cookies: {r.cookies} <br>"
            yield f"Request headers: {r.headers} <br>"
            yield f"Request environ: {r.environ} <br>"
            yield f"Request script_root: {r.script_root} <br>"
            yield f"Request url: {r.url} <br>"
            yield f"Request base_url: {r.base_url} <br>"
            yield f"Request url_root: {r.url_root} <br>"
            yield "</div>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            yield f"Values: {values} <br>"
            yield "</div>"
            yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
            yield f"Settings: {settings} <br>"
            yield "</div>"

            # Check processes
            yield "<h2>Processes</h2>"
            yield "<p style='color: darkgray'>Checking processes by ps command...</p>"
            try:
                processes = []
                ps = subprocess.check_output(["ps", "aux"]).decode()
                processes = ps.split("\n")
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                processes = None

            if processes is None:
                # check processes by proc filesystem
                yield "<p style='color: darkgray'>Checking processes by proc filesystem...</p>"
                try:
                    processes = []
                    proc_files = subprocess.check_output(["ls /proc/*/cmdline"], shell=True, text=True)
                    proc_array = proc_files.split("\n")
                    for proc in proc_array:
                        if len(proc) == 0:
                            continue
                        if "self" in proc:
                            continue
                        if os.path.isfile(proc):
                            with open(proc, "r") as f:
                                content = f.read()
                                args = [arg for arg in content.split("\x00") if arg]
                                processes.append(" ".join(args))
                except Exception as e:
                    yield f"<p style='color: red'>Error: {e}</p>"
                    processes = None

            if processes is not None:
                yield "<h3>Processes</h3>"
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                for process in processes:
                    yield f"{process} <br>"
                yield "</div>"

            # Network access
            yield "<h2>Network access</h2>"
            yield "<p style='color: darkgray'>Checking network access...</p>"

            # Check HTTPBin
            yield "<h3>HTTPBin info</h3>"
            try:
                httpbin_ip = requests.get("https://httpbin.org/ip").json()
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                httpbin_ip = None

            if httpbin_ip is not None:
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                yield f"HTTPBin IP: {httpbin_ip} <br>"
                yield "</div>"

            # Check AWS
            yield "<h2>AWS credentials</h2>"
            sts = boto3.client("sts")
            arn = None
            try:
                yield "<p style='color: darkgray'>Checking AWS credentials...</p>"
                caller_identity = sts.get_caller_identity()
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                caller_identity = None

            if caller_identity is not None:
                yield "<h3>Caller identity info</h3>"
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                if "Account" in caller_identity:
                    yield f"Account: {caller_identity["Account"]} <br>"
                if "UserId" in caller_identity:
                    yield f"UserId: {caller_identity["UserId"]} <br>"
                if "Arn" in caller_identity:
                    yield f"Arn: {caller_identity["Arn"]} <br>"
                    arn = caller_identity["Arn"]
                yield "</div>"

            yield "<h2>IAM/Role info</h2>"
            yield "<p style='color: darkgray'>Checking IAM/Role info...</p>"
            iam = boto3.client("iam")

            parts = arn.split("/") if arn is not None else []
            if len(parts) == 0:
                yield "<p style='color: red'>No user or role found in ARN</p>"
            if len(parts) > 1:
                role_header = parts[0]
                if parts[0].endswith("user"):
                    pass
                if role_header.endswith("role") or role_header.endswith("assumed-role"):
                    role_name = parts[1]

                    # Get role info
                    try:
                        yield "<p style='color: darkgray'>Checking role...</p>"
                        role_info = iam.get_role(RoleName=role_name)
                    except Exception as e:
                        yield f"<p style='color: red'>Error: {e}</p>"
                        role_info = None

                    if role_info is not None:
                        yield "<h3>Role info</h3>"
                        yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                        if "Role" in role_info:
                            role = role_info["Role"]
                            if "RoleName" in role:
                                yield f"Role name: {role['RoleName']} <br>"
                            if "RoleId" in role:
                                yield f"Role ID: {role['RoleId']} <br>"
                            if "Arn" in role:
                                yield f"Role ARN: {role['Arn']} <br>"
                            if "AssumeRolePolicyDocument" in role:
                                yield f"Assume role policy: {role['AssumeRolePolicyDocument']} <br>"
                        yield "</div>"

                    # Get attached policies
                    try:
                        yield "<p style='color: darkgray'>Checking attached policies...</p>"
                        attached_poloicies = iam.list_attached_role_policies(RoleName=role_name)
                    except Exception as e:
                        yield f"<p style='color: red'>Error: {e}</p>"
                        attached_poloicies = None

                    if attached_poloicies is not None:
                        yield "<h3>Attached policies</h3>"
                        for policy in attached_poloicies["AttachedPolicies"]:
                            if "PolicyName" in policy:
                                yield f"Attached policy: {policy['PolicyName']} <br>"
                            if "PolicyArn" in policy:
                                yield f" -> Attached policy ARN: {policy['PolicyArn']} <br>"
                            policy_details = iam.get_policy(PolicyArn=policy["PolicyArn"])
                            if policy_details is not None:
                                yield f" -> Attached policy details: {policy_details} <br>"

                    # Get inline policies
                    try:
                        yield "<p style='color: darkgray'>Checking inline policies...</p>"
                        inline_policies = iam.list_role_policies(RoleName=role_name)
                    except Exception as e:
                        yield f"<p style='color: red'>Error: {e}</p>"
                        inline_policies = None

                    if inline_policies is not None:
                        for policy_name in inline_policies["PolicyNames"]:
                            yield f"Inline policy: {policy_name} <br>"
                            try:
                                inline_policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            except Exception as e:
                                yield f"Error getting inline policy: {e} <br>"
                            if inline_policy is not None:
                                yield f" -> Inline policy: {inline_policy} <br>"

            # Extra
            yield "<h2>Extra</h2>"

            # Check all files in root directory
            yield "<p style='color: darkgray'>Checking root directory...</p>"
            try:
                results = []
                for root, _dirs, files in os.walk("/"):
                    for file in files:
                        results.append(os.path.join(root, file))
            except Exception as e:
                yield f"<p style='color: red'>Error: {e}</p>"
                results = None

            if results is not None:
                yield "<h3>Root directory files</h3>"
                yield "<div style='margin: 10px; border: 1px solid black; padding: 10px'>"
                # print file max 1000

                for i, file in enumerate(results):
                    if i > 1000:
                        yield "<p style='color: darkgray'>Too many files, stopping...</p>"
                        break
                    yield f"{file} <br>"
                yield "</div>"
            else:
                yield "<p style='color: red'>No files found</p>"

            yield "</body>"
            yield "</html>"

        return Response(generator(), status=200, content_type="text/html")
