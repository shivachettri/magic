import os
import platform
import yaml
import logging
import subprocess
import concurrent.futures
import re
import fnmatch
import urllib.request
import json


# Read configuration from a YAML file

config_yaml = '''
all:
  git:
    g_git: "github" # "github" or "gitlab"
    project_id: '42403605'
    g_email: "chettri@live.com"
    g_dev_repo: "https://github.com/AnjaniGourisaria/codeigniter3.git" # url convention for git is https://{hub/lab}.com/{user}/{repo}.git
    g_prod_repo: "" # url convention for git is https://{hub/lab}.com/{user}/{repo}.git
    g_username: "AnjaniGourisaria"
    g_token: "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"

  nginx:
    n_domain: "code.com"
    n_sub_domain: ""
    n_folder: "code.com"

  sql:
    s_use_existing_user: "yes" # to continue with same sql credentials choose "yes" if not then "no" 
    s_username: "testing"
    s_password: "root@P21222"
    s_database: "testing"


  sql_root_credentials:  # if new machine directly run the auto-hosting.py
    sr_port: "3306"
    sr_host: "localhost"
    sr_user: "root"
    sr_passwd: "" # After installation of mysql the password will be ""

  custom:
    c_protocol: "https://" # for config.php
    c_choose: "no" # to configure ssh so you can login
    c_do_mysql_secure_installation: "no" # to setup mysql root password "yes" or "no" and it uses sql_root_credentials   if you want to change password you can use it '''


config = yaml.load(config_yaml, Loader=yaml.FullLoader)

# Define a new logging level called SUCCESS

class ColoredFormatter(logging.Formatter):
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    green = "\x1b[32;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_str = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: green + format_str + reset,
        logging.INFO: grey + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)



# Create a logger and set the formatter
logging.basicConfig(filename='setup.log', level=logging.DEBUG, format='%(asctime)s:%(levelname)s:%(message)s', datefmt='%d-%m-%Y %H:%M:%S')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)

# Check the php fpm sock version by visiting the above folder

def setup_sql_config(s_database, s_username, s_password):
    config='''
      CREATE DATABASE {0};
      CREATE USER "{1}"@"localhost" IDENTIFIED BY "{2}";
      GRANT ALL PRIVILEGES ON {0}.* TO "{1}"@"localhost";
      FLUSH PRIVILEGES;
    '''.format(s_database,s_username,s_password)

    with open("/tmp/{0}.sql".format(s_database), "w") as f:
        f.write(config)

def setup_sql(sql):
    logging.info("################################################################################################################################################################################  Setup SQL #")
    
    setup_sql_config(sql['s_database'], sql['s_username'], sql['s_password'])
    os.system("sudo mysql < /tmp/{0}.sql".format(sql['s_database']))
    os.system("sudo rm -rf /tmp/{0}.sql".format(sql['s_database']))


def setup_nginx_config(n_domain, n_folder, n_sub_domain,n_file):
    config = '''server {{
  listen 80;
  listen [::]:80;
  root /var/www/{0};
  index index.php index.html;
  server_name {1} {2};
  location / {{
    try_files $uri $uri/ /index.php;
  }}
  location ~ \.php$ {{
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/{3};
  }}
  location ~ /\.ht {{
    deny all;
  }}
  location ~ /\.git {{
    deny all;
  }}
}}
'''.format(n_folder, n_domain, n_sub_domain,n_file)

    with open("/etc/nginx/sites-available/{0}".format(n_domain), "w") as f:
        f.write(config)





def setup_nginx(nginx):
    logging.info("################################################################################################################################################################################  Setup Nginx #")    
    path = "/var/run/php/"
    pattern = re.compile(r"php\d+\.\d+-fpm\.sock$")
    for filename in os.listdir(path):
        if pattern.match(filename):
            n_file=filename

    setup_nginx_config(nginx['n_domain'],nginx['n_folder'],nginx['n_sub_domain'], n_file)
    os.system("sudo ln -s /etc/nginx/sites-available/{0} /etc/nginx/sites-enabled/".format(nginx['n_domain']))
    os.system("sudo systemctl restart nginx")


def prod(git,n_folder,g_dev_repo):
    g_prod_repo = git['g_prod_repo'].split("/")[-1][:-4]

    project_dir_prod = os.path.join('/tmp', n_folder)
    os.makedirs(project_dir_prod, exist_ok=True)
    
    subprocess.run(f"git clone {git['g_prod_repo']}", cwd=project_dir_prod, shell=True)
    subprocess.run(f"rm -rf /var/www/{n_folder}/.git && mv {project_dir_prod}/{g_prod_repo}/.git /var/www/{n_folder}/", shell=True)


def setup_git(git,n_folder):
    
    logging.info("###################################################################################################################################################################################### Setup Git #")
    subprocess.call('git config --global credential.helper store', shell=True)
    subprocess.call("echo 'protocol=https\nhost={2}.com\nusername={0}\npassword={1}\n' | git credential approve".format(git['g_username'], git['g_token'],git['g_git']), shell=True)
    project_dir = os.path.join('/var', 'www', n_folder)
    os.makedirs(project_dir, exist_ok=True)

    # Set the user name and email for Git
    subprocess.run(f"git config --global user.email {git['g_email']}", shell=True)
    subprocess.run(f"git config --global user.name {git['g_username']}", shell=True)

    # Move the repository files to the project directory and set the safe directory
    g_dev_repo = git['g_dev_repo'].split("/")[-1][:-4]

    subprocess.run(f"git clone {git['g_dev_repo']}", cwd=project_dir, shell=True)
    subprocess.run(f"rsync -a --remove-source-files /var/www/{n_folder}/{g_dev_repo}/ /var/www/{n_folder}/ ",shell=True)
    
    if(git['g_prod_repo'] != ''):
        prod(git,n_folder,g_dev_repo)

    # subprocess.run("mv -f /var/www/{0}/{1}/* /var/www/{0}/{1}/.* /var/www/{0}/ ".format(n_folder,g_dev_repo),shell=True)
    subprocess.run(f"git config --global --add safe.directory {project_dir}", shell=True)

    # Set the correct file permissions
    subprocess.run(['chown', '-R', 'www-data:www-data', project_dir])
    subprocess.run(['chmod', '-R', '700', project_dir])


def custom_setup(custom, nginx, sql):
    logging.info("################################################################################################################################################################################  Config.php & database.php #")
    config_file = f"/var/www/{nginx['n_folder']}/application/config/config.php"
    database_file = f"/var/www/{nginx['n_folder']}/application/config/database.php"
    try:
        with open(config_file) as f:
            for line in f:
                if line.startswith("$config['base_url']"):
                    base_url = line.split("=")[1].strip().strip(";").strip("'")
                    data = None
                    with open(config_file) as infile:
                        data = infile.read()
                    if data is not None:
                        data = data.replace(
                            base_url, f"{custom['c_protocol']}{nginx['n_domain']}")
                        logging.info(
                            f"Replacing {base_url} with {custom['c_protocol']}{nginx['n_domain']} in {config_file}")
                        with open(config_file, 'w') as outfile:
                            outfile.write(data)
                        break

        with open(database_file) as f:
            data = f.read()

        data = re.sub(r"('username' => ').*(',)",
                      "\\1{0}\\2".format(sql['s_username']), data)
        data = re.sub(r"('password' => ').*(',)",
                      "\\1{0}\\2".format(sql['s_password']), data)
        data = re.sub(r"('database' => ').*(',)",
                      "\\1{0}\\2".format(sql['s_database']), data)

        with open(database_file, 'w') as outfile:
            outfile.write(data)
            logging.info(
                f"Successfully replaced password and database values in {database_file}")

    except Exception as e:
        logging.info(f"Exception as {e}")


def ssh_keygen(c_choose, ipv4, ipv6):
    logging.info("########################################################################################################################################################################################### SSH Kegen #")
    logging.info("Choose User from the list {0}".format(os.listdir("/home/")))
    c_user = str(input("Enter full Username to add ssh key: "))
    c_key = str(input("Enter full 'id_rsa.pub' form '~./.ssh/id_rsa.pub' if not available the 'ssh-keygen -o' then follow the same : "))
    if (os.path.exists("/home/{0}/.ssh/".format(c_user))):
        with open("/home/{0}/.ssh/authorized_keys".format(c_user), "a") as f:
            f.write(c_key)
        if (ipv4 != ''):
            print("ssh {0}@{1}".format(c_user, ipv4))
        elif (ipv6 != ''):
            print("ssh {0}@{1}".format(c_user, ipv6))



def execute_sql_query(query, host, port, user, password, flag=False):
    try:
        with open(os.path.join(os.environ['HOME'], '.sql'), 'w') as f:
            f.write(f"[client]\nuser={user}\npassword={password}\n")
        cmd = f"mysql --defaults-extra-file=$HOME/.sql -h {host} -P {port} -e '{query}'"
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        if (flag):
            return output.split("\n")[1]
        # print(output)
        # print(len(output))
        return output
    except subprocess.CalledProcessError:
        logging.error("Error executing MySQL command")
        err = "1"



def check_repo_exists(g_git,user,repo_name,token,project_id=''):
    if (g_git == "github"):
        try:
            github_url = f"https://api.github.com/repos/{user}/{repo_name}"
            github_req = urllib.request.Request(github_url)
            github_req.add_header('Authorization', f'token {token}')

            github_resp = urllib.request.urlopen(github_req)
            github_data = json.loads(github_resp.read().decode('utf-8'))
        except Exception as e:
            logging.warning(f"Github check Repo name and username  {e}")
            exit()
    elif(g_git == "gitlab"):
        try:
            url = f"http://gitlab.com/api/v4/projects/{project_id}/"
            headers = {"PRIVATE-TOKEN": token}
            # Send the API request and get the response
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req)
            response = str(json.loads(response.read().decode('utf-8'))).lower()
            if not f"{repo_name}".lower() in response   or not f"{user}".lower() in response:
                logging.error("Gitlab  repo not found or check user or project id")
                exit()
        except Exception as e:
            logging.error("Gitlab check repo  or  username or project id ")
            exit()


def sys_check(all):
    logging.info("############################################################################################################################################################################################## Checking #")
    err = "0"

    def check_empty(all, exception_vars=None):
        empty_variables = []
        for key, value in all.items():
            if isinstance(value, dict):
                inner_empty_vars = [f"{key}.{inner_key}" for inner_key, inner_value in value.items() if (
                    inner_key not in exception_vars and (not inner_value or str(inner_value).isspace()))]
                empty_variables.extend(inner_empty_vars)
            else:
                if key not in exception_vars and (not value or str(value).isspace()):
                    empty_variables.append(key)
        if empty_variables:
            logging.warning(f"The following config  are empty: {', '.join(empty_variables)}")
            err = "1"

    exception_vars = ['g_prod_repo', 'n_sub_domain', 'sr_passwd','project_id']
    check_empty(all, exception_vars)

    def validate_password(password):
        pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()-_+={[}\]|:;"<>,.?]).{8,}$'
        return bool(re.match(pattern, password))

    if (not validate_password(all['sql']['s_password'])):
        logging.warning("Sql: sql.s_password: Password must be 8+ characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 special character.")
        err = "1"

    g_dev_repo = all['git']['g_dev_repo'].split("/")[-1][:-4]

    if (all['git']['g_git'] == "github"):
        # GitHub API request
        github_url = 'https://api.github.com/user'
        github_req = urllib.request.Request(github_url)
        github_req.add_header('Authorization', f'token {all["git"]["g_token"]}')

        try:
            github_resp = urllib.request.urlopen(github_req)
            github_data = json.loads(github_resp.read().decode('utf-8'))
            if "login" in github_data:
                check_repo_exists(all['git']['g_git'],all['git']['g_username'],g_dev_repo,all['git']['g_token'])
        
        except urllib.error.HTTPError as e:
            logging.error(f'Github: Error {e.code}: {e.reason}, Status Code: {e.status}')
            err = "1"
    elif (all['git']['g_git'] == "gitlab"):
        # GitLab API request
        gitlab_url = 'https://gitlab.com/api/v4/user'
        gitlab_req = urllib.request.Request(gitlab_url)
        gitlab_req.add_header('Authorization', f'Bearer {all["git"]["g_token"]}')

        try:
            gitlab_resp = urllib.request.urlopen(gitlab_req)
            gitlab_data = json.loads(gitlab_resp.read().decode('utf-8'))
            if "username" in gitlab_data:
                check_repo_exists(all['git']['g_git'],all['git']['g_username'],g_dev_repo,all['git']['g_token'],all['git']['project_id'])
        except urllib.error.HTTPError as e:
            logging.error(f'GitLab: Error {e.code}: {e.reason}, Status Code: {e.status}')
            err = "1"
    else:
        logging.error("Git: Using Unsupported Git")
        err = "1"

    sql = all['sql_root_credentials']
    query = f"SELECT CAST(COUNT(*) AS UNSIGNED) as c FROM mysql.user WHERE User = \"{all['sql']['s_username']}\""
    s1=execute_sql_query(query, sql['sr_host'], sql['sr_port'], sql['sr_user'], sql['sr_passwd'], True)
    s_use_existing_user=all['sql']['s_use_existing_user']

    if(s_use_existing_user == "yes"):
        if (int(s1) == 0):
            logging.warning(f"Sql: sql.s_username User {all['sql']['s_username']} does not exists")
            err="1"
    elif (int(s1) > 0):
        logging.warning(f"Sql: sql.s_username User {all['sql']['s_username']} exists")
        err = "1"

    query = f"SHOW DATABASES LIKE \"{all['sql']['s_database']}\";"
    s1=execute_sql_query(query, sql['sr_host'], sql['sr_port'], sql['sr_user'], sql['sr_passwd']).strip()
    if(s_use_existing_user == "yes"):
        if (len(s1.split('\n')) == 1):
            logging.warning(f"Sql: sql.s_database Database {all['sql']['s_database']} does not exists")
            err="1"
    elif (s1):
        logging.warning(f"Sql: sql.s_database: Database {all['sql']['s_database']} exists")
        err = "1"
 
    
    del sql



    if (os.path.isdir("/var/www/{0}".format(all['nginx']['n_folder']))):
        logging.warning(f"Nginx: Directory /var/www/{all['nginx']['n_folder']}  exists")
        err = "1"

    if (g_dev_repo == ''):
        logging.warning(f"Git: Convention not followed by a git repo {g_dev_repo}")
        err = "1"

    if (all['git']['g_prod_repo'] != ''):
        g_prod_repo = all['git']['g_prod_repo'].split("/")[-1][:-4]
        check_repo_exists(all['git']['g_git'],all['git']['g_username'],g_prod_repo,all['git']['g_token'])

        if (g_prod_repo == ''):
            logging.warning(f"Git: Convention not followed by a git repo {g_prod_repo}")
            err = "1"
        elif (g_dev_repo == g_prod_repo):
            logging.warning(f"Git: Dev repo can't be same with a Prod git repo {g_dev_repo} == {g_prod_repo}")
            err = "1"

        if ((os.path.exists(f"/tmp/{all['nginx']['n_folder']}") or os.path.exists(f"/tmp/{all['nginx']['n_folder']}/{g_prod_repo}"))):
            logging.warning(f"The directory /tmp/{all['nginx']['n_folder']} or  does /tmp/{all['nginx']['n_folder']}/{g_prod_repo} exists.")
            err = "1"


    if ((os.path.exists(f"/etc/nginx/sites-available/{all['nginx']['n_domain']}") or os.path.islink(f"/etc/nginx/sites-enabled/{all['nginx']['n_domain']}"))):
        logging.warning(f"The directory /etc/nginx/sites-available or /etc/nginx/sites-enabled/ does  exists '{all['nginx']['n_domain']}' .")
        err = "1"
    


    if (err == "1"):
        exit()


def generate_password():
    import string
    import secrets
    while True:
        # Generate a random string of 8 characters
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8))
        
        # Check if the password meets the criteria
        if any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password):
            return password


def mysql_secure_installation(sql):
    logging.info("################################################################################################################################################################################ Mysql Secure Setup #")

    mysql_root_password= generate_password()

    commands = [
        f"SET GLOBAL validate_password.policy=MEDIUM;",
        f"ALTER USER \"root\"@\"localhost\" IDENTIFIED  BY \"{mysql_root_password}\";",
        f"FLUSH PRIVILEGES;"
    ]

    for cmd in commands:
        execute_sql_query(cmd, sql['sr_host'], sql['sr_port'], sql['sr_user'], sql['sr_passwd'])
        
    logging.info(f"custom.c_do_mysql_secure_installation \033[32m Passowrd set for root is :  {mysql_root_password}  \033[0m")


def get_sql(n_folder, s_database):
    root_dir = f"/var/www/{n_folder}"
    file_pattern = '*.sql'

    for root, dirs, files in os.walk(root_dir):
        for filename in fnmatch.filter(files, file_pattern):
            path = os.path.join(root, filename)
            print(f"SQL file found at: {path}")
            # Prompt the user to continue with this path
            choice = input("Do you want to continue with this path? (y/n): ")
            if choice.lower() == "y":
                # User wants to continue, do something with the path here
                print(f"Processing SQL file at: {path}")
                os.system(f"sudo mysql {s_database} < {path}")
                continue
                # Example: execute the SQL file on the specified database
            else:
                # User doesn't want to continue, skip to next iteration of the loop
                continue

def cleanup(n_folder,s_database,g_dev_repo):
    os.system(f"rm -rf /tmp/{n_folder}")
    os.system(f"rm -rf /var/www/{n_folder}/{g_dev_repo}")
    config=f"os.system(\"cd /var/www/{n_folder} && sudo mysqldump --defaults-extra-file=$HOME/.sql {s_database} > THE_DATABASE_BACKUP.sql && git add . && git commit -m 'Back Up'  && git push\")"
    if(os.path.exists('/root/backup.py')):
        os.system(f"echo '{config}' >> /root/backup.py")
    else:
        imports="import os\n"
        config=imports+config
        os.system(f"echo '{config}' > /root/backup.py")
    os.system(f"cd /var/www/{n_folder} && git branch -m main && git checkout main && git add . && git commit -m '....' && git push")


def setup(ipv4='',ipv6=''):
    logging.info("\033[32m Starting Setup \033[0m")
    sys_check(config['all'])
    setup_git(config['all']['git'],config['all']['nginx']['n_folder'])
    setup_nginx(config['all']['nginx'])
    if(config['all']['sql']['s_use_existing_user'] != "yes"): setup_sql(config['all']['sql'])
    custom_setup(config['all']['custom'],config['all']['nginx'],config['all']['sql'])
    get_sql(config['all']['nginx']['n_folder'],config['all']['sql']['s_database'])

    if(config['all']['custom']['c_choose'] =='yes'): ssh_keygen(config['all']['custom']['c_choose'],ipv4,ipv6)
    if(config['all']['custom']['c_do_mysql_secure_installation'] == "yes"): mysql_secure_installation(config['all']['sql_root_credentials'])
    cleanup(config['all']['nginx']['n_folder'],config['all']['sql']['s_database'],config['all']['git']['g_dev_repo'])
    logging.info("To Flush Clouldfare DNS: https://1.1.1.1/purge-cache/")
    logging.info("To Flush Google DNS: https://developers.google.com/speed/public-dns/cache")
    logging.info(f"IPv4 address: {ipv4}")
    if(ipv6!=''): logging.info(f"IPv6 address: {ipv6}")
    logging.info("\033[32m Make sure you setup a cronjob : crontab -e \033[0m")
    logging.info(" \033[32m For Morning 9 and evening 9 do :  0 9,21 * * * python3 ~/backup.py | Once a day: 0 0 * * * python3 ~/backup.py \033[0m]")
    logging.info("\033[32m Setup complete \033[0m")


def main():
    if os.geteuid() != 0:
        logging.error('This program is not running with sudo')
        exit()

    arch = platform.machine()
    ipv4 , ipv6 = '',''
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            ipv4 = executor.submit(subprocess.check_output, "curl -s ipv4.icanhazip.com", shell=True).result().decode().strip()
            ipv6 = executor.submit(subprocess.check_output, "curl -s ipv6.icanhazip.com", shell=True).result().decode().strip()
    except Exception as e:
            pass

    if arch == "x86_64":
        packages = "nginx mysql-server php-fpm php-mysql certbot git"
    elif arch == "armv6l":
        packages = "nginx mariadb-server mariadb-client php-fpm php-mysql certbot git"
    else:
        logging.error(f"Unsupported architecture: {arch}")
        return
    #os.system("sudo apt update && sudo apt full-upgrade -y && sudo apt install -y " + packages)

    setup(ipv4,ipv6)
if __name__ == '__main__':
    main()
